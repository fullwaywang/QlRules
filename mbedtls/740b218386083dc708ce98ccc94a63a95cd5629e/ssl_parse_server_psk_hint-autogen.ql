/**
 * @name mbedtls-740b218386083dc708ce98ccc94a63a95cd5629e-ssl_parse_server_psk_hint
 * @id cpp/mbedtls/740b218386083dc708ce98ccc94a63a95cd5629e/ssl-parse-server-psk-hint
 * @description mbedtls-740b218386083dc708ce98ccc94a63a95cd5629e-library/ssl_cli.c-ssl_parse_server_psk_hint CVE-2018-9989
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_2048, Parameter vend_2049, Parameter vssl_2047, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2048
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_2049
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_debug_print_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vssl_2047
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="bad server key exchange message (psk_identity_hint length)"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-31488"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_2048, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2048
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2048
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_2(Parameter vp_2048, Parameter vend_2049, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2048
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vend_2049
}

predicate func_3(Parameter vssl_2047, ExprStmt target_3) {
		target_3.getExpr().(VariableAccess).getTarget()=vssl_2047
}

predicate func_4(Parameter vssl_2047, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("mbedtls_debug_print_msg")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vssl_2047
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="bad server key exchange message (psk_identity_hint length)"
}

from Function func, Parameter vp_2048, Parameter vend_2049, Parameter vssl_2047, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vp_2048, vend_2049, vssl_2047, target_1, target_2, target_3, target_4, func)
and func_1(vp_2048, target_1)
and func_2(vp_2048, vend_2049, target_2)
and func_3(vssl_2047, target_3)
and func_4(vssl_2047, target_4)
and vp_2048.getType().hasName("unsigned char **")
and vend_2049.getType().hasName("unsigned char *")
and vssl_2047.getType().hasName("mbedtls_ssl_context *")
and vp_2048.getParentScope+() = func
and vend_2049.getParentScope+() = func
and vssl_2047.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
