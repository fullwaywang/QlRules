/**
 * @name mbedtls-a1098f81c252b317ad34ea978aea2bc47760b215-ssl_parse_server_key_exchange
 * @id cpp/mbedtls/a1098f81c252b317ad34ea978aea2bc47760b215/ssl-parse-server-key-exchange
 * @description mbedtls-a1098f81c252b317ad34ea978aea2bc47760b215-library/ssl_cli.c-ssl_parse_server_key_exchange CVE-2018-9988
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vend_2269, Variable vp_2269, Parameter vssl_2264, FunctionCall target_1, EqualityOperation target_2, EqualityOperation target_3, AddressOfExpr target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_2269
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_2269
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_debug_print_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vssl_2264
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="bad server key exchange message"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_ssl_send_alert_message")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vssl_2264
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="50"
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-31488"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(FunctionCall target_1) {
		target_1.getTarget().hasName("mbedtls_ssl_ciphersuite_uses_server_signature")
}

predicate func_2(Variable vend_2269, Variable vp_2269, Parameter vssl_2264, EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("ssl_parse_signature_algorithm")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vssl_2264
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_2269
		and target_2.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vend_2269
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vend_2269, Variable vp_2269, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vend_2269
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_2269
}

predicate func_4(Variable vp_2269, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vp_2269
}

predicate func_5(Variable vp_2269, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_2269
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_2269
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_6(Parameter vssl_2264, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("mbedtls_debug_print_msg")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vssl_2264
		and target_6.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_6.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_6.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_6.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="should never happen"
}

predicate func_7(Parameter vssl_2264, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("mbedtls_debug_print_msg")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vssl_2264
		and target_7.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="bad server key exchange message"
}

from Function func, Variable vend_2269, Variable vp_2269, Parameter vssl_2264, FunctionCall target_1, EqualityOperation target_2, EqualityOperation target_3, AddressOfExpr target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vend_2269, vp_2269, vssl_2264, target_1, target_2, target_3, target_4, target_5, target_6, target_7)
and func_1(target_1)
and func_2(vend_2269, vp_2269, vssl_2264, target_2)
and func_3(vend_2269, vp_2269, target_3)
and func_4(vp_2269, target_4)
and func_5(vp_2269, target_5)
and func_6(vssl_2264, target_6)
and func_7(vssl_2264, target_7)
and vend_2269.getType().hasName("unsigned char *")
and vp_2269.getType().hasName("unsigned char *")
and vssl_2264.getType().hasName("mbedtls_ssl_context *")
and vend_2269.getParentScope+() = func
and vp_2269.getParentScope+() = func
and vssl_2264.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
