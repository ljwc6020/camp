package com.camp.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Scanner;

@RestController
@Log4j2
@RequestMapping("/camping")
@RequiredArgsConstructor
public class CampController {
    @Value("${api.service.key}")
    private String apiKey;


    @GetMapping("/basedList")
    @ResponseBody
    public String basedList(
            @RequestParam(required = false) String numOfRows,
            @RequestParam(required = false) String pageNo
    ) {
        StringBuilder result = new StringBuilder();
        try {
            String apiUrl = "http://apis.data.go.kr/B551011/GoCamping/basedList?" +
                    "serviceKey=" + apiKey;
            if (pageNo != null) {
                apiUrl += "&pageNo=" + pageNo;
            }
            apiUrl += "&MobileOS=WIN" +
                    "&MobileApp=camp" +
                    "&numOfRows=5"+
                    "&_type=json";

            log.info(apiUrl);

            URL url = new URL(apiUrl);
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestMethod("GET");

            Scanner scanner = new Scanner(urlConnection.getInputStream(), "UTF-8");
            while (scanner.hasNextLine()) {
                result.append(scanner.nextLine());
            }
            urlConnection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result.toString() ;
    }


    @GetMapping("/locationBasedList")
    @ResponseBody
    // 위치 기반으로 목록 보여주는 컨트롤러 WGS84 , 경도 위도로 조건을 받습니다.
    public String locationBasedList(
            @RequestParam(required = false) String pageNo,
            @RequestParam(required = true)  String mapX,
            @RequestParam(required = true) String mapY
    ) {
        StringBuilder result = new StringBuilder();
        try {
            String apiUrl = "http://apis.data.go.kr/B551011/GoCamping/locationBasedList?" +
                    "serviceKey=" + apiKey +
                    "&mapX=" + mapX + //경도
                    "&mapY=" + mapY; // 위도

            if (pageNo != null) {
                apiUrl += "&pageNo=" + pageNo;
            }
            apiUrl += "&MobileOS=WIN" +
                    "&MobileApp=camp" +
                    "&radius=10000"+
                    "&numOfRows=5"+
                    "&_type=json";

            log.info(apiUrl);
            URL url = new URL(apiUrl);
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestMethod("GET");

            Scanner scanner = new Scanner(urlConnection.getInputStream(), "UTF-8");
            while (scanner.hasNextLine()) {
                result.append(scanner.nextLine());
            }
            urlConnection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result.toString();
    }

    @GetMapping("/searchList")
    @ResponseBody
    // keyword 로 검색하는 컨트롤러
    public String searchList(
            @RequestParam(required = false) String pageNo,
            @RequestParam(required = false) String keyword
    ) throws UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();
        log.info(URLDecoder.decode(keyword));
        try {
            String apiUrl = "http://apis.data.go.kr/B551011/GoCamping/searchList?" +
                    "serviceKey=" + apiKey +"&keyword="+URLEncoder.encode(keyword,"UTF-8");
            if (pageNo != null) {
                apiUrl += "&pageNo=" + pageNo;
            }
            apiUrl += "&MobileOS=WIN" +
                    "&MobileApp=camp" +
                    "&numOfRows=5"+
                    "&_type=json";

            log.info(apiUrl);
            URL url = new URL(apiUrl);
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestMethod("GET");

            Scanner scanner = new Scanner(urlConnection.getInputStream(), "UTF-8");
            while (scanner.hasNextLine()) {
                result.append(scanner.nextLine());
            }
            urlConnection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result.toString();
    }



    @GetMapping("/imageList")
    @ResponseBody
    // 이미지를 가져오는 컨트롤러, 요청은 성공하는대 이미지를 어떻게 보여줄지 감이 안옵니다.
    // contentID 값을 써야하기 때문에 저희는 일일이 쓰기 힘들지도?
    // 일단 json 형식으로 받아오는 데이터중 imageUrl 이라되어 있는 부분이 실제 이미지 주소 입니다.
    public String imageList(@RequestParam String contentId) {

        StringBuilder result = new StringBuilder();
        try {

            String apiUrl = "http://apis.data.go.kr/B551011/GoCamping/imageList?" +
                    "serviceKey=" + apiKey +
                    "&MobileOS=WIN" +
                    "&MobileApp=camp" +
                    "&contentId="+contentId+
                    "&_type=json";

            log.info(apiUrl);

            URL url = new URL(apiUrl);
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestMethod("GET");

            Scanner scanner = new Scanner(urlConnection.getInputStream(), "UTF-8");
            while (scanner.hasNextLine()) {
                result.append(scanner.nextLine());
            }
            urlConnection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "<pre>" + result.toString() + "</pre>";

    }


    @GetMapping("/basedSyncList")
    @ResponseBody
    // 업데이트된 상태를 보여주는 컨트롤러, 솔직히 이건 안쓸거 같긴 합니다
    public String basedSyncList(@RequestParam String pageNO,
                                @RequestParam String numOfRows,
                                @RequestParam String syncStatus,
                                @RequestParam String syncModTime) {

        StringBuilder result = new StringBuilder();
        try {

            String apiUrl = "http://apis.data.go.kr/B551011/GoCamping/basedSyncList?" +
                    "serviceKey=" + apiKey +
                    "&numOfRows=" +numOfRows+
                    "&pageNo=" +pageNO+
                    "&MobileOS=WIN" +
                    "&MobileApp=camp" +
                    // 상태, A 추가 U 업데이트 D 딜리트, 일단 주석처리
                    "&syncStatus=" +syncStatus+
                    // 수정일자, 년도, 년월, 년월일 입력 가능, 일단 주석처리
                    "&syncModTime= "+syncModTime+
                    "&_type=json";

            URL url = new URL(apiUrl);
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestMethod("GET");

            Scanner scanner = new Scanner(urlConnection.getInputStream(), "UTF-8");
            while (scanner.hasNextLine()) {
                result.append(scanner.nextLine());
            }
            urlConnection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "<pre>" + result.toString() + "</pre>";

    }



}