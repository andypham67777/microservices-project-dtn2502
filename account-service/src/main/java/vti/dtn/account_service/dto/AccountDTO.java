package vti.dtn.account_service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class AccountDTO {
    private Integer id;
    private String userName;
    private String firstName;
    private String lastName;
    private String role;
    private String departmentName;
    private Integer departmentId;
}
