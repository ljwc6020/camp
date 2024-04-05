package com.camp.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ImageDTO {

    private String prediction;
    private String name;
    private String address;
    private String campPhone;
    private String imagePath;

}