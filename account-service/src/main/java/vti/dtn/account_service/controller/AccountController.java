package vti.dtn.account_service.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vti.dtn.account_service.dto.AccountDTO;
import vti.dtn.account_service.services.AccountService;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "api/v1/accounts")
public class AccountController {
    // gọi services để xử lý logic
    private final AccountService accountService;

    @GetMapping
    public List<AccountDTO> getListAccounts() {
        return accountService.getListAccounts();
    }
}
