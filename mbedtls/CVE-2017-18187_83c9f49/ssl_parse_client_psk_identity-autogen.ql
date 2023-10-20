/**
 * @name mbedtls-83c9f495ffe70c7dd280b41fdfd4881485a3bc28-ssl_parse_client_psk_identity
 * @id cpp/mbedtls/83c9f495ffe70c7dd280b41fdfd4881485a3bc28/ssl-parse-client-psk-identity
 * @description mbedtls-83c9f495ffe70c7dd280b41fdfd4881485a3bc28-library/ssl_srv.c-ssl_parse_client_psk_identity CVE-2017-18187
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vend_3423, BlockStmt target_10, LogicalOrExpr target_11) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_3423
		and target_0.getLesserOperand().(PointerArithmeticOperation).getRightOperand() instanceof PointerDereferenceExpr
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_10
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_3422, Parameter vend_3423, LogicalOrExpr target_11, PointerDereferenceExpr target_12, RelationalOperation target_8) {
	exists(PointerArithmeticOperation target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vend_3423
		and target_1.getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_3422
		and target_1.getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_12.getOperand().(VariableAccess).getLocation())
		and target_8.getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vp_3422, PointerDereferenceExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vp_3422
}

predicate func_3(Parameter vp_3422, PointerDereferenceExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vp_3422
}

predicate func_5(Parameter vend_3423, BlockStmt target_10, VariableAccess target_5) {
		target_5.getTarget()=vend_3423
		and target_5.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_5.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_10
}

predicate func_6(Variable vn_3426, VariableAccess target_6) {
		target_6.getTarget()=vn_3426
}

predicate func_7(Parameter vend_3423, VariableAccess target_7) {
		target_7.getTarget()=vend_3423
}

predicate func_8(Parameter vend_3423, BlockStmt target_10, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getGreaterOperand().(PointerArithmeticOperation).getAnOperand() instanceof PointerDereferenceExpr
		and target_8.getGreaterOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vend_3423
		and target_8.getParent().(IfStmt).getThen()=target_10
}

predicate func_9(Variable vn_3426, PointerArithmeticOperation target_9) {
		target_9.getAnOperand() instanceof PointerDereferenceExpr
		and target_9.getAnOperand().(VariableAccess).getTarget()=vn_3426
}

predicate func_10(BlockStmt target_10) {
		target_10.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_debug_print_msg")
		and target_10.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_10.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_10.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_10.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="bad client key exchange message"
}

predicate func_11(Parameter vend_3423, Variable vn_3426, LogicalOrExpr target_11) {
		target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vn_3426
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_3426
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65535"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vend_3423
}

predicate func_12(Parameter vp_3422, PointerDereferenceExpr target_12) {
		target_12.getOperand().(VariableAccess).getTarget()=vp_3422
}

from Function func, Parameter vp_3422, Parameter vend_3423, Variable vn_3426, PointerDereferenceExpr target_2, PointerDereferenceExpr target_3, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, RelationalOperation target_8, PointerArithmeticOperation target_9, BlockStmt target_10, LogicalOrExpr target_11, PointerDereferenceExpr target_12
where
not func_0(vend_3423, target_10, target_11)
and not func_1(vp_3422, vend_3423, target_11, target_12, target_8)
and func_2(vp_3422, target_2)
and func_3(vp_3422, target_3)
and func_5(vend_3423, target_10, target_5)
and func_6(vn_3426, target_6)
and func_7(vend_3423, target_7)
and func_8(vend_3423, target_10, target_8)
and func_9(vn_3426, target_9)
and func_10(target_10)
and func_11(vend_3423, vn_3426, target_11)
and func_12(vp_3422, target_12)
and vp_3422.getType().hasName("unsigned char **")
and vend_3423.getType().hasName("const unsigned char *")
and vn_3426.getType().hasName("size_t")
and vp_3422.getParentScope+() = func
and vend_3423.getParentScope+() = func
and vn_3426.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
