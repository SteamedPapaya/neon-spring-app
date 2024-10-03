package com.nemo.chat.controller;

import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.stereotype.Controller;

@Controller
public class ChatController {

    @MessageMapping("/chat/messages")
    @SendTo("/topic/chat/messages")
    public String sendMessage(String message, SimpMessageHeaderAccessor headerAccessor) {
        // 여기에서 받은 메시지를 처리하고, 클라이언트로 브로드캐스트
        return message;
    }
}
