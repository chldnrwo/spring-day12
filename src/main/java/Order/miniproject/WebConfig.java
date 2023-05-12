package Order.miniproject;

import Order.miniproject.filter.LogFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;

@Configuration
public class WebConfig {

  @Bean
  public FilterRegistrationBean logFilter(){
    FilterRegistrationBean<Filter> fRBean =
        new FilterRegistrationBean<>();
    fRBean.setFilter(new LogFilter());
    fRBean.setOrder(1);
    fRBean.addUrlPatterns("/*");
    return fRBean;
  }
}
