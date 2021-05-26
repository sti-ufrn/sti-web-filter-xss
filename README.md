sti-web-filter-xss
--

Filtro de segurança que previve ataques XSS (Cross-Site Scripting) em requisições nos 
sistemas que o utilizam.

### Build

Descrever o build...

### Utilização

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
