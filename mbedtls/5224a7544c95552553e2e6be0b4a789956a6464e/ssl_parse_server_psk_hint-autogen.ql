/**
 * @name mbedtls-5224a7544c95552553e2e6be0b4a789956a6464e-ssl_parse_server_psk_hint
 * @id cpp/mbedtls/5224a7544c95552553e2e6be0b4a789956a6464e/ssl-parse-server-psk-hint
 * @description mbedtls-5224a7544c95552553e2e6be0b4a789956a6464e-library/ssl_cli.c-ssl_parse_server_psk_hint CVE-2018-9989
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vend_2049, Variable vlen_2052, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(PointerArithmeticOperation target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vend_2049
		and target_0.getRightOperand().(VariableAccess).getTarget()=vlen_2052
		and target_0.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_0.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vend_2049
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
		and target_6.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(VariableAccess).getLocation())
		and target_0.getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_2048, PointerDereferenceExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vp_2048
}

predicate func_2(Variable vlen_2052, VariableAccess target_2) {
		target_2.getTarget()=vlen_2052
}

predicate func_3(Parameter vend_2049, BlockStmt target_5, VariableAccess target_3) {
		target_3.getTarget()=vend_2049
		and target_3.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Parameter vend_2049, Variable vlen_2052, BlockStmt target_5, PointerArithmeticOperation target_4) {
		target_4.getAnOperand() instanceof PointerDereferenceExpr
		and target_4.getAnOperand().(VariableAccess).getTarget()=vlen_2052
		and target_4.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vend_2049
		and target_4.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_debug_print_msg")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="bad server key exchange message (psk_identity_hint length)"
}

predicate func_6(Parameter vp_2048, Parameter vend_2049, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2048
		and target_6.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_2049
		and target_6.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="2"
}

predicate func_7(Parameter vp_2048, Variable vlen_2052, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_2052
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2048
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2048
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_8(Parameter vp_2048, Variable vlen_2052, ExprStmt target_8) {
		target_8.getExpr().(AssignPointerAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2048
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vlen_2052
}

from Function func, Parameter vp_2048, Parameter vend_2049, Variable vlen_2052, PointerDereferenceExpr target_1, VariableAccess target_2, VariableAccess target_3, PointerArithmeticOperation target_4, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vend_2049, vlen_2052, target_5, target_6, target_7, target_8)
and func_1(vp_2048, target_1)
and func_2(vlen_2052, target_2)
and func_3(vend_2049, target_5, target_3)
and func_4(vend_2049, vlen_2052, target_5, target_4)
and func_5(target_5)
and func_6(vp_2048, vend_2049, target_6)
and func_7(vp_2048, vlen_2052, target_7)
and func_8(vp_2048, vlen_2052, target_8)
and vp_2048.getType().hasName("unsigned char **")
and vend_2049.getType().hasName("unsigned char *")
and vlen_2052.getType().hasName("size_t")
and vp_2048.getParentScope+() = func
and vend_2049.getParentScope+() = func
and vlen_2052.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
