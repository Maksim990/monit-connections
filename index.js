const pcap = require("pcap");

const pcapSession = pcap.createSession("enp2s0", { promisc: false });
let socketPorts = {"cn": {on: 0, off: 0}};
let time = 0;

function uptime(uptimeInSeconds) {
            const secondsInMinute = 60;
            const secondsInHour = 3600;
            const secondsInDay = 86400;

            const days = Math.floor(uptimeInSeconds / secondsInDay);
            const hours = Math.floor((uptimeInSeconds % secondsInDay) / secondsInHour);
            const minutes = Math.floor((uptimeInSeconds % secondsInHour) / secondsInMinute);
            const seconds = Math.floor(uptimeInSeconds % secondsInMinute);

            return `${days}:${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}.${seconds.toString().padStart(2, '0')}`;
        }

setInterval(() => time += 60, 1000);

pcapSession.on("packet", rawPacket => {
    const _packet = pcap.decode.packet(rawPacket);
    const packet = _packet.payload.payload;
    const protocols = {
        1: "ICMP",
		2: "IGMP",
        6: "TCP",
        17: "UDP"
    };

    //IPv4 пакет
    if (_packet.link_type === 'LINKTYPE_ETHERNET' && _packet.payload.ethertype === 0x0800) {
        const protocol = protocols[packet.protocol] || packet.protocol;
        const sourceIP = packet.saddr.addr.join(".");
        const destIP = packet.daddr.addr.join(".");
        const sourcePort = packet.payload.sport;
        const destPort = packet.payload.dport;
        const packetLen = packet.length;

        if (packet.protocol == 6 && !packet.payload.flags.rst) {
        	socketPorts.cn.off++;
        };

        if (packet.protocol == 6) {
        	if (!socketPorts[sourcePort]) {
        		socketPorts[sourcePort] = [];
        	};

        	if (packet.payload.flags.rst) {
        		socketPorts[sourcePort] = socketPorts[sourcePort].filter(ip => ip !== sourceIP);
        	} else {
        		if (!socketPorts[sourcePort].includes(sourceIP)) {
        			socketPorts.cn.on++;
		            socketPorts[sourcePort].push(sourceIP);
		        }
        	}

        	if (socketPorts[sourcePort].length == 0) delete socketPorts[sourcePort];
        };

        //console.log(`Передан ${protocol} с размером ${packetLen} байт: ${sourceIP}:${sourcePort} -> ${destIP}:${destPort}`);
    };
});

pcapSession.on("error", function (err) {
    console.error("Ошибка при работе с pcap:", err);
});

const blessed = require('blessed');

// Создаем объект экрана
const screen = blessed.screen({
  smartCSR: true,
  title: 'Список соединений',
});

// Создаем объект окна прокрутки
const scrollable = blessed.box({
  parent: screen,
  top: 0,
  left: 0,
  width: '100%',
  height: '100%',
  scrollable: true,
  alwaysScroll: true,
  scrollbar: {
    ch: ' ',
    inverse: true,
  },
  style: {
    fg: 'white',
    bg: 'black',
  },
});

let scrollPosition = 0; // Переменная для отслеживания позиции скролла
async function countConnections() {
    let conn = 0;
    for (const key in socketPorts) {
        if (key == "cn") continue;
        conn += socketPorts[key].length;
    }
    return conn;
}
// Функция для обновления текста в окне прокрутки с сохранением позиции скролла
async function updateText() {
  const currentScroll = scrollable.getScroll();
  const shouldScrollDown = currentScroll + 1 >= scrollable.getScrollHeight();

	let conn = await countConnections();
  
  let txt = `Текущие подключения: ${conn}/TCP\nПодключено: ${socketPorts.cn.on}/с | Отключено: ${socketPorts.cn.off}/с\nВремя мониторинга ${uptime(time)}\n---\n`;
  for (const key in socketPorts) {
  	if (key == "cn") continue;
  	//txt = `${require("util").inspect(socketPorts[443], { colors: true })}`;
    txt += `type: TCP   port: ${key}   connections: ${socketPorts[key].length}\n`;
  }
  socketPorts.cn.on = 0;
  socketPorts.cn.off = 0;
  
  scrollable.setContent(txt);
  
  if (shouldScrollDown) {
    scrollable.setScroll(scrollable.getScrollHeight()); // Прокручиваем вниз, если были внизу
  } else {
    scrollable.setScroll(currentScroll); // Восстанавливаем позицию скролла
  }

  screen.render();
}

// Устанавливаем интервал обновления текста
setInterval(updateText, 1000);

// Обработка события завершения работы
screen.key(['C-c'], function(ch, key) {
  return process.exit(0);
});

// Обработка событий клавиш "верх" и "вниз"
screen.key(['up'], function(ch, key) {
  scrollable.scroll(-1); // Прокрутка вверх
  screen.render();
});

screen.key(['down'], function(ch, key) {
  scrollable.scroll(1); // Прокрутка вниз
  screen.render();
});

// Инициализируем экран и окно
screen.render();
updateText();
