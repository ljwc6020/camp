package com.camp.util;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import net.coobird.thumbnailator.Thumbnails;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
@Log4j2
@RequiredArgsConstructor
public class CustomFileUtil {

    @Value("${com.camp.upload.path}")
    private String uploadPath;

    @PostConstruct
    public void init() {
        // 파일 업로드 경로 설정
        File tempFolder = new File(uploadPath);
        if (!tempFolder.exists()) {
            tempFolder.mkdir();
        }
        uploadPath = tempFolder.getAbsolutePath();

        log.info("-------------------------------------");
        log.info(uploadPath);
    }

    // 파일 저장 메서드
    public List<String> saveFiles(List<MultipartFile> files) {
        List<String> uploadNames = new ArrayList<>();

        try {
            for (MultipartFile multipartFile : files) {
                String savedName = getUniqueFileName(multipartFile.getOriginalFilename());
                Path savePath = Paths.get(uploadPath, savedName);
                Files.copy(multipartFile.getInputStream(), savePath);

                if (isImageFile(multipartFile.getContentType())) {
                    createThumbnail(savePath, savedName);
                }

                uploadNames.add(savedName);
            }
        } catch (IOException e) {
            log.error("Error occurred while saving files: {}", e.getMessage());
            throw new FileStorageException("Failed to store files", e);
        }

        return uploadNames;
    }

    // 파일 이름에 UUID를 붙여 고유하게 만드는 메서드
    private String getUniqueFileName(String originalFilename) {
        return UUID.randomUUID().toString() + "_" + originalFilename;
    }

    // 이미지 파일인지 확인하는 메서드
    private boolean isImageFile(String contentType) {
        return contentType != null && contentType.startsWith("image");
    }

    // 썸네일 생성 메서드
    private void createThumbnail(Path filePath, String fileName) throws IOException {
        Path thumbnailPath = Paths.get(uploadPath, "s_" + fileName);
        Thumbnails.of(filePath.toFile())
                .size(200, 200)
                .toFile(thumbnailPath.toFile());
    }

    // 파일 다운로드 메서드
    public ResponseEntity<Resource> getFile(String fileName) {
        try {
            Resource resource = new FileSystemResource(Paths.get(uploadPath, fileName).toString());

            if (!resource.isReadable()) {
                resource = new FileSystemResource(Paths.get(uploadPath, "winter.jpg").toString());
            }

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_TYPE, Files.probeContentType(resource.getFile().toPath()));

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(resource);
        } catch (IOException e) {
            log.error("Error occurred while retrieving file: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    // 파일 삭제 메서드
    public void deleteFiles(List<String> fileNames) {
        for (String fileName : fileNames) {
            deleteFile(fileName);
        }
    }

    // 개별 파일 삭제 메서드
    private void deleteFile(String fileName) {
        try {
            Path filePath = Paths.get(uploadPath, fileName);
            Files.deleteIfExists(filePath);

            Path thumbnailPath = Paths.get(uploadPath, "s_" + fileName);
            Files.deleteIfExists(thumbnailPath);
        } catch (IOException e) {
            log.error("Error occurred while deleting file {}: {}", fileName, e.getMessage());
            throw new FileStorageException("Failed to delete file " + fileName, e);
        }
    }

    // 파일 저장 예외 처리 클래스
    public static class FileStorageException extends RuntimeException {
        public FileStorageException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
