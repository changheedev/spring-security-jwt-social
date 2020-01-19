# 프로젝트 생성 및 DB 연결 설정

---



## 프로젝트 생성

---



https://start.spring.io 에서 아래 4가지 라이브러리를 추가한 후 프로젝트를 생성합니다.

- Web 
- Security
- JPA
- Lombok 
  - 이클립스 및 Intellij 설치방법 : https://www.baeldung.com/lombok-ide



## DB 설정

---



MariaDB를 사용하기 위해 도커를 통해 MariaDB를 설치합니다.



### MariaDB 설치

아래 링크로 접속하여 도커를 다운 받은 후 설치합니다.

https://hub.docker.com/

설치가 완료되면 제대로 설치 되었는지 아래 명령어를 실행해봅니다.

```
docker -version
docker run hello-world
```



MariaDB 이미지를 설치합니다.

```
docker pull mariadb:latest
```



### 컨테이너 실행

컨테이너를 실행하는 방법으로는 명령어로 실행하는 방법과 docker-compose 를 이용하는 방법이 있습니다.



#### 명령어로 실행

```
docker run --name mariadb -e MYSQL_ROOT_PASSWORD=password -p 13306:3306 -d mariadb:latest 
```

- **--name** : 컨테이너의 이름을 설정

- **MYSQL_ROOT_PASSWORD** : MariaDB 의 root 계정 패스워드 설정
- **-p {호스트 포트} : {컨테이너 포트}** : 호스트 포트로 온 요청을 컨테이너 포트로 포워딩 한다. (외부 프로그램에서 db에 접속할 때 호스트 포트를 이용해 접속하게 됩니다.)
- **-d** : 백그라운드 모드로 실행



#### docker-compose

실행 스크립트를 docker-compose.yml 파일에 작성해놓으면 매번 실행시 마다 명령어를 적어주지 않아도 됩니다.

```
version: '3'
services:
  mariadb:
    image: mariadb:latest
    restart: always
    environment:
      - MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PW}
    volumes:
      - ${MYSQL_DATA_PATH}:/var/lib/mysql
      - ${MYSQL_CONFIG_PATH}:/etc/mysql/conf.d
    ports:
      - 13306:3306
```

- **version** : docker 엔진 버전
- **mariadb** : 컨테이너 이름
- **restart** : 재실행 설정
- **environment** : 환경변수 값 설정
- **volumes** : 컨테이너를 재실행하면 새로운 DB 컨테이너를 실행한 것과 같기 때문에 기존 DB 데이터가 날라가게 됩니다. DB 데이터를 계속 유지하려면 별도의 디렉토리로 마운트를 해주어야 합니다.
- **ports** : 포트 포워딩 설정



**.env**

DB 계정 정보와 같이 노출되면 안되는 정보들은 .env 파일에 작성 후 읽어오게 할 수 있습니다. 

버전 관리에 포함되지 않도록 .gitignore 파일에 등록해줍니다.

```
MYSQL_ROOT_PW=...
MYSQL_DATA_PATH=...
MYSQL_CONFIG_PATH=...
```



**실행**

```
docker-compose up -d
```



**실행중인 프로세스 확인**

```
docker ps
```



**컨테이너 접속하기**

```
docker exec -it CONTAINER_NAME bash
```



**비밀번호 변경시 Column ‘Password’ is not updatable 발생할 경우**

MySQL 5.7 버전 이상부터는 루트 계정의 패스워드를 변경하는 쿼리가 변경 되었습니다.

```
set PASSWORD for ‘계정’@’host' = PASSWORD(‘바꿀 비밀번호’);
```



### 프로젝트에서 MariaDB 컨테이너 연결

**build.gradle**

```
dependencies{
	implementation 'org.mariadb.jdbc:mariadb-java-client:2.5.2'
}
```



**application.yml** 

```yml
spring:
  datasource:
    url: jdbc:mariadb://127.0.0.1:13306/exam?useSSL=false&serverTimezone=Asia/Seoul
    username: #DB 계정 username
    password: #DB 계정 password
    driver-class-name: org.mariadb.jdbc.Driver
```



### JPA 설정

**application.yml**

```yaml
spring:
  datasource: ...
	jpa:
    show-sql: true #실행된 쿼리를 출력
    hibernate:
      ddl-auto: create
    database-platform: org.hibernate.dialect.MariaDB103Dialect
    properties:
      hibernate:
        format_sql: true #출력되는 쿼리를 가독성 있게 변경
        use_sql_comments: true #실행하는 쿼리에 대한 정보를 보여준다 (엔티티, 쿼리 종류 등)
```

**ddl-auto** 

애플리케이션을 시작할 때마다 엔티티 맵핑 설정을 DB 스키마에 반영하는 방법에 대한 설정입니다.

create 나 update 로 설정하면 별도로 테이블을 생성하거나 변경하는 작업을 대신 해주기 때문에 간편하지만 운영 환경에서는  데이터에 영향을 주기 때문에 개발 용도로만 사용하는 것을 추천드립니다.

validate 로 설정하면 엔티티와 테이블이 제대로 매핑되는지 검증하고 실패시 애플리케이션을 종료합니다.

