package com.camp.controller;

import com.camp.domain.Image;
import com.camp.repository.ImageRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;


@RestController
@Log4j2
@RequiredArgsConstructor
public class ImageController {

    private final ImageRepository imageRepository;

    @GetMapping("/{prediction}")
    public ResponseEntity<?> getByPrediction(@PathVariable String prediction) {

        log.info("similar camping location is here : " + prediction);

           Optional<Image> image = imageRepository.findByPrediction(prediction);
           return ResponseEntity.ok(image);
       }
}
