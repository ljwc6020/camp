package com.camp.config;

import com.camp.domain.Image;
import com.camp.repository.ImageRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@RequiredArgsConstructor
@Configuration
@Log4j2
public class DataInitializer {

    private final ImageRepository imageRepository;

    @Bean
    CommandLineRunner initDatabase() {
        log.info("___________________Image Data run___________________");
        String imagePathMountain = "images/mountain.jpg";
        String imagePathSea = "images/sea.jpg";

        return args -> {
            imageRepository.save(new Image("mountain","동두천 파인힐빌리지캠핑장", "경기 동두천시 안흥로 65-42", "010-3552-5084",imagePathMountain ));
            imageRepository.save(new Image("sea","거제산달바다 캠핑장", "경남 거제시 거제면 소랑리 176-4","010-8535-6644",imagePathSea ));
        };
    }
}
