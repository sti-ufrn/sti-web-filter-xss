sti-web-filter-xss
--

Filtro que previne ataques XSS (Cross-Site Scripting) em requisições nos sistemas que o 
utilizam.

### Dependências

* Java 6

### Referências

- [Maven Getting Started Guide](https://maven.apache.org/guides/getting-started/index.html)
- [Working with the Apache Maven registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry)

### Build

Executado o comando abaixo, os artefatos gerados estarão disponíveis na pasta ` target ` 
do projeto e serão instalados no ` repositório local ` do maven, assim podendo ser 
utilizado como dependência em projetos locais.

```
mvnw clean install
```

### Utilização

Para utilização com gerenciadores de dependência, é necessário configurar o repositório do 
GitHub da STI/UFRN no projeto (ver **Referências**, *Working with the Apache Maven registry*).

Maven:
```xml
<dependency>
    <groupId>br.ufrn.sti.web.filters</groupId>
    <artifactId>sti-web-filter-xss</artifactId>
    <version>X.Y.Z</version>
</dependency>
```

Gradle:
```groovy
compile(group: 'br.ufrn.sti.web.filters', name: 'sti-web-filter-xss', version: 'X.Y.Z')
```

SIGs UFRN:
```groovy
ufrnInternalLib(group: 'br.ufrn.sti.web.filters', name: 'sti-web-filter-xss', version: 'X.Y.Z')
```

A dependência abaixo também deve ser declarada nos projetos que não usam o mecanismo de
dependência transitória.

Maven:
```xml
<dependency>
    <groupId>org.owasp.esapi</groupId>
    <artifactId>esapi</artifactId>
    <version>2.1.0.1</version>
</dependency>
```

Gradle:
```groovy
compile(group: 'org.owasp.esapi', name: 'esapi', version: '2.1.0.1')
```

SIGs UFRN:
```groovy
deployLib(group: 'org.owasp.esapi', name: 'esapi', version: '2.1.0.1')
```

### Configuração
O filtro deve ser adicionado ao arquivo `web.xml` do projeto conforme exemplo abaixo.

```xml

<filter>
    <filter-name>XSSPrevention</filter-name>
    <filter-class>XSSFilterbr.ufrn.sti.web.filters.xss.XSSFilter</filter-class>
    <!-- Ativa o registro do log em caso de suspeita de XSS -->
    <init-param>
        <param-name>logging</param-name>
        <param-value>true</param-value>
    </init-param>
    <!-- forward: (redireciona para uma outra url - forwardTo) 
         protect: (Irá remover o conteúdo da requisição)
         throw: (Lançará uma exceção caso encontre algum código suspeito) -->
    <init-param>
        <param-name>behavior</param-name>
        <param-value>forward</param-value>
    </init-param>
    <!-- Apenas para o behavior "forward" -->
    <init-param>
        <param-name>forwardTo</param-name>
        <param-value>/shared/public/null.jsp</param-value>
    </init-param>
    <init-param>
        <param-name>excludedUrls</param-name>
        <!-- Lista (separada por vírgula) de URLs onde a utilização de sql é permitida -->
        <param-value>/portal,/html-editor</param-value>
    </init-param>
</filter>
```

```xml
<filter-mapping>
	<filter-name>XSSPrevention</filter-name>
	<url-pattern>/*</url-pattern>
</filter-mapping>
```

### Autores

* **Arlindo Rodrigues** - *Software Engineer* - [arlindonatal@gmail.com](mailto:arlindonatal@gmail.com)
* **Raphael Medeiros** - *Software Engineer* - [raphael.medeiros@gmail.com](mailto:raphael.medeiros@gmail.com)