#/bin/bash

echo $(whoami)

sed -i 's/#HiddenServiceDir \/var\/lib\/tor\/hidden_service\//HiddenServiceDir \/var\/lib\/tor\/hidden_service\//' /etc/tor/torrc

sed -i '0,/#HiddenServicePort 80 127.0.0.1:80/ s/#HiddenServicePort 80 127.0.0.1:80/HiddenServicePort 80 127.0.0.1:9000/' /etc/tor/torrc

tor &

tor_pid=$(echo $!)

while true
do
    if [ -d "/var/lib/tor/hidden_service" ]; then
        echo "found directory, killing tor"
        kill -9 $tor_pid
        rm /var/lib/tor/hidden_service/private_key
        cp /hidden_service/private_key /var/lib/tor/hidden_service
        echo "starting tor again"
        tor &
        break
    fi
    echo "finding directory in 5s"
    sleep 5
done

sleep 10
echo $(cat /var/lib/tor/hidden_service/hostname)

echo "starting python server..."
cd /share && python3.7 -m http.server 9000