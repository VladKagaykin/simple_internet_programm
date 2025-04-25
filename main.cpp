#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <iostream>
#include <vector>
#include <map>
#include <thread>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/steady_timer.hpp>

using namespace boost::asio;
using ip::tcp;
using namespace std;

// Функция получения внешнего IP
string get_external_ip() {
    try {
        io_service io_service;
        tcp::resolver resolver(io_service);
        tcp::resolver::query query("ifconfig.me", "80");
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        connect(socket, endpoint_iterator);

        string request = "GET /ip HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n";
        write(socket, buffer(request));

        boost::asio::streambuf response;
        read_until(socket, response, "\r\n\r\n");
        read_until(socket, response, "\r\n");

        stringstream ss;
        ss << &response;
        string full_response = ss.str();

        size_t pos = full_response.find("\r\n\r\n");
        if(pos != string::npos) {
            return full_response.substr(pos+4);
        }
    } catch (exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
    }
    return "Не удалось получить внешний IP";
}

// Функция получения имени хоста
string host() {
    return ip::host_name();
}

// Функция получения IPv4
string ipv4() {
    try {
        io_service io_service;
        tcp::resolver resolver(io_service);
        auto endpoints = resolver.resolve(host(), "");

        for (auto it = endpoints; it != tcp::resolver::iterator(); ++it) {
            auto addr = it->endpoint().address();
            if (addr.is_v4()) {
                return addr.to_string();
            }
        }
    } catch (const exception& e) {
        cerr << "Ошибка получения IPv4: " << e.what() << endl;
    }
    return "";
}

// Функция получения IPv6
string ipv6() {
    try {
        io_service io_service;
        tcp::resolver resolver(io_service);
        auto endpoints = resolver.resolve(host(), "");

        for (auto it = endpoints; it != tcp::resolver::iterator(); ++it) {
            auto addr = it->endpoint().address();
            if (addr.is_v6()) {
                return addr.to_string();
            }
        }
    } catch (const exception& e) {
        cerr << "Ошибка получения IPv6: " << e.what() << endl;
    }
    return "";
}

// Переименованная функция вывода IP-информации
int show_ip_info() {
    try {
        cout << "Имя хоста: " << host() << endl;
        string v4 = ipv4();
        string v6 = ipv6();

        cout << "Внутренние IP-адреса:\n";
        if (!v4.empty()) cout << "IPv4: " << v4 << endl;
        if (!v6.empty()) cout << "IPv6: " << v6 << endl;
        cout << "Ваш внешний IP-адрес: " << get_external_ip() << endl;

    } catch (const exception& ex) {
        cerr << "Исключение: " << ex.what() << endl;
        return 1;
    }
    return 0;
}

// Сканирование локальной сети
void scan_local_network() {
    try {
        io_service io_service;
        vector<string> local_ips;
        string hostname = host();
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(hostname, "");
        tcp::resolver::iterator endpoints = resolver.resolve(query);

        for (; endpoints != tcp::resolver::iterator(); ++endpoints) {
            auto addr = endpoints->endpoint().address();
            if (addr.is_v4()) {
                local_ips.push_back(addr.to_string());
            }
        }

        if (local_ips.empty()) return;

        string base_ip = local_ips[0].substr(0, local_ips[0].rfind('.') + 1);
        cout << "\nСканирование локальной сети (" << base_ip << "X):\n";

        for (int i = 1; i < 255; ++i) {
            string target_ip = base_ip + to_string(i);
            tcp::endpoint ep(ip::make_address_v4(target_ip), 80);

            tcp::socket socket(io_service);
            boost::asio::steady_timer timer(io_service);
            bool connected = false;

            socket.async_connect(ep, [&](auto) { connected = true; });
            timer.expires_from_now(boost::asio::chrono::milliseconds(500));
            timer.async_wait([&](auto) { socket.close(); });

            io_service.reset();
            io_service.run_one();

            if (connected) {
                try {
                    tcp::resolver dns_resolver(io_service);
                    tcp::resolver::query dns_query(tcp::v4(), target_ip, "");
                    auto it = dns_resolver.resolve(dns_query);
                    if(it != tcp::resolver::iterator()) {
                        string hostname = it->host_name();
                        cout << target_ip << " - " << hostname << '\n';
                    }
                } catch (system_error& e) {
                    cout << target_ip << " - ошибка DNS: " << e.what() << '\n';
                }
            }
        }
    } catch (...) {}
}

// VPN-сервер
class VPNServer {
    io_service& io_service_;
    tcp::acceptor acceptor_;
    map<string, tcp::socket> clients_;
    string buffer_;

public:
    VPNServer(io_service& service, short port) 
        : io_service_(service), 
          acceptor_(service, tcp::endpoint(tcp::v4(), port)) 
    {
        start_accept();
    }

    void start_accept() {
        auto socket = make_shared<tcp::socket>(io_service_);
        acceptor_.async_accept(*socket, [this, socket](const error_code& ec) {
            if (!ec) {
                async_read_until(*socket, dynamic_buffer(buffer_), "\n",
                    [this, socket](const error_code& ec, size_t) {
                        if (!ec) {
                            string client_name(buffer_.substr(0, buffer_.find('\n')));
                            clients_.emplace(client_name, std::move(*socket));
                            cout << "Клиент подключен: " << client_name << endl;
                            buffer_.clear();
                        }
                    });
            }
            start_accept();
        });
    }
};

// VPN-клиент
class VPNClient {
    io_service& io_service_;
    tcp::socket socket_;
    string server_ip_;
    short port_;
    string buffer_;

public:
    VPNClient(io_service& service, const string& ip, short port) 
        : io_service_(service), socket_(service), server_ip_(ip), port_(port) {}

    void connect(const string& client_name) {
        tcp::resolver resolver(io_service_);
        auto endpoints = resolver.resolve(server_ip_, to_string(port_));
        async_connect(socket_, endpoints, 
            [this, client_name](const error_code& ec, const tcp::endpoint&) {
                if (!ec) {
                    async_write(socket_, buffer(client_name + "\n"),
                        [](const error_code&, size_t) {});
                    start_receive();
                }
            });
    }

    void start_receive() {
        async_read_until(socket_, dynamic_buffer(buffer_), "\n",
            [this](const error_code& ec, size_t) {
                if (!ec) {
                    cout << "Получено: " << buffer_ << endl;
                    buffer_.clear();
                    start_receive();
                }
            });
    }
};

shared_ptr<VPNServer> vpn_server;
shared_ptr<VPNClient> vpn_client;
thread server_thread;

void start_vpn_server(int port) {
    try {
        io_service service;
        vpn_server = make_shared<VPNServer>(service, port);
        service.run();
    } catch (exception& e) {
        cerr << "Ошибка сервера: " << e.what() << endl;
    }
}

void connect_to_vpn(const string& ip, int port, const string& client_name) {
    try {
        io_service service;
        vpn_client = make_shared<VPNClient>(service, ip, port);
        vpn_client->connect(client_name);
        service.run();
    } catch (exception& e) {
        cerr << "Ошибка подключения: " << e.what() << endl;
    }
}

// Обновленная справка
int help() {
    cout << "Список команд:\n"
         << "  help          - Показать это меню\n"
         << "  exit          - Выйти из программы\n"
         << "  host          - Показать имя хоста\n"
         << "  local         - Сканировать локальную сеть\n"
         << "  ip            - Показать информацию об IP-адресах\n"
         << "  external_ip   - Показать внешний IP\n"
         << "  ipv4          - Показать IPv4 адрес\n"
         << "  ipv6          - Показать IPv6 адрес\n"
         << "  vpn_server    - Запустить VPN сервер\n"
         << "  vpn_connect   - Подключиться к VPN серверу\n";
    return 0;
}

// Обработчик команд
int switch_function() {
    string user;
    while(user != "exit") {
        cout << "> ";
        cin >> user;

        if(user == "host") {
            cout << host() << endl;
        }
        else if(user == "local") {
            scan_local_network();
        }
        else if(user == "ip") {
            show_ip_info();
        }
        else if(user == "external_ip") {
            cout << get_external_ip() << endl;
        }
        else if(user == "ipv4") {
            cout << ipv4() << endl;
        }
        else if(user == "ipv6") {
            cout << ipv6() << endl;
        }
        else if(user == "help") {
            help();
        }
        else if(user == "vpn_server") {
            int port;
            cout << "Введите порт: ";
            cin >> port;
            server_thread = thread(start_vpn_server, port);
            cout << "VPN сервер запущен на порту " << port << endl;
        }
        else if(user == "vpn_connect") {
            string ip, name;
            int port;
            cout << "IP сервера: ";
            cin >> ip;
            cout << "Порт: ";
            cin >> port;
            cout << "Ваше имя: ";
            cin >> name;
            thread(connect_to_vpn, ip, port, name).detach();
            cout << "Подключение к " << ip << ":" << port << "..." << endl;
        }
        else if(user != "exit") {
            cout << "Неизвестная команда. Введите 'help' для списка команд.\n";
        }
    }
    
    if(server_thread.joinable()) {
        server_thread.join();
    }
    return 0;
}

int main() {
    cout << "Сетевой инструмент с VPN функциями\n";
    help();
    switch_function();
    return 0;
}
