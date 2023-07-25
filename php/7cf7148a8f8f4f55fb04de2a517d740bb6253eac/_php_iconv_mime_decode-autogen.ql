/**
 * @name php-7cf7148a8f8f4f55fb04de2a517d740bb6253eac-_php_iconv_mime_decode
 * @id cpp/php/7cf7148a8f8f4f55fb04de2a517d740bb6253eac/-php-iconv-mime-decode
 * @description php-7cf7148a8f8f4f55fb04de2a517d740bb6253eac-ext/iconv/iconv.c-_php_iconv_mime_decode CVE-2019-11039
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstr_left_1491, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstr_left_1491
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vstr_left_1491, EqualityOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vstr_left_1491
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(CharLiteral).getValue()="61"
}

predicate func_3(Variable vstr_left_1491, ExprStmt target_3) {
		target_3.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vstr_left_1491
}

from Function func, Variable vstr_left_1491, ExprStmt target_1, EqualityOperation target_2, ExprStmt target_3
where
not func_0(vstr_left_1491, target_2, target_3, target_1)
and func_1(vstr_left_1491, target_2, target_1)
and func_2(target_2)
and func_3(vstr_left_1491, target_3)
and vstr_left_1491.getType().hasName("size_t")
and vstr_left_1491.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
