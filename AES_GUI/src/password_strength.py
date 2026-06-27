# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
import re


@dataclass(frozen=True)
class PasswordStrengthResult:
    score: int
    level: str
    color: str
    suggestions: list[str] = field(default_factory=list)


class PasswordStrengthService:
    _common_passwords = {
        "1234", "123456", "12345678", "password", "qwerty",
        "admin", "admin123", "111111", "000000", "abc123",
    }

    def evaluate(self, password: str, username: str = "") -> PasswordStrengthResult:
        if not password:
            return PasswordStrengthResult(0, "未输入", "#909399", ["请输入密码"])

        score = 0
        suggestions: list[str] = []
        length = len(password)

        if length >= 12:
            score += 35
        elif length >= 10:
            score += 30
        elif length >= 8:
            score += 24
        elif length >= 6:
            score += 16
        else:
            score += 8
            suggestions.append("建议至少 8 位")

        checks = [
            (bool(re.search(r"[a-z]", password)), 12, "增加小写字母"),
            (bool(re.search(r"[A-Z]", password)), 12, "增加大写字母"),
            (bool(re.search(r"\d", password)), 12, "增加数字"),
            (bool(re.search(r"[^A-Za-z0-9]", password)), 14, "增加特殊字符"),
        ]
        variety = 0
        for ok, points, suggestion in checks:
            if ok:
                score += points
                variety += 1
            else:
                suggestions.append(suggestion)

        if variety >= 3:
            score += 10
        if variety == 4:
            score += 5

        lower_password = password.lower()
        lower_username = username.lower().strip()
        if lower_password in self._common_passwords:
            score -= 35
            suggestions.append("避免常见弱口令")
        if lower_username and lower_username in lower_password:
            score -= 20
            suggestions.append("避免包含用户名")
        if re.search(r"(.)\1{3,}", password):
            score -= 15
            suggestions.append("避免连续重复字符")
        if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer)", lower_password):
            score -= 10
            suggestions.append("避免连续键盘或数字序列")

        score = max(0, min(100, score))
        suggestions = suggestions[:3]
        if score < 40:
            return PasswordStrengthResult(score, "弱", "#e74c3c", suggestions or ["请提高密码复杂度"])
        if score < 70:
            return PasswordStrengthResult(score, "中", "#e67e22", suggestions or ["可继续增加复杂度"])
        return PasswordStrengthResult(score, "强", "#27ae60", suggestions or ["密码强度良好"])
