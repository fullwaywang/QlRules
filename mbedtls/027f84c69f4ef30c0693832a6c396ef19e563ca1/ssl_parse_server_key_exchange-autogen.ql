/**
 * @name mbedtls-027f84c69f4ef30c0693832a6c396ef19e563ca1-ssl_parse_server_key_exchange
 * @id cpp/mbedtls/027f84c69f4ef30c0693832a6c396ef19e563ca1/ssl-parse-server-key-exchange
 * @description mbedtls-027f84c69f4ef30c0693832a6c396ef19e563ca1-library/ssl_cli.c-ssl_parse_server_key_exchange CVE-2018-9988
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vend_2269, Variable vsig_len_2429, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(PointerArithmeticOperation target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vend_2269
		and target_0.getRightOperand().(VariableAccess).getTarget()=vsig_len_2429
		and target_0.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vend_2269
		and target_0.getParent().(NEExpr).getAnOperand() instanceof PointerArithmeticOperation
		and target_0.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_5
		and target_6.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(VariableAccess).getLocation())
		and target_0.getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getLocation()))
}

predicate func_1(Variable vend_2269, BlockStmt target_5, VariableAccess target_1) {
		target_1.getTarget()=vend_2269
		and target_1.getParent().(NEExpr).getAnOperand() instanceof PointerArithmeticOperation
		and target_1.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_2(Variable vp_2269, VariableAccess target_2) {
		target_2.getTarget()=vp_2269
}

predicate func_3(Variable vsig_len_2429, VariableAccess target_3) {
		target_3.getTarget()=vsig_len_2429
}

predicate func_4(Variable vp_2269, Variable vend_2269, Variable vsig_len_2429, BlockStmt target_5, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vp_2269
		and target_4.getAnOperand().(VariableAccess).getTarget()=vsig_len_2429
		and target_4.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vend_2269
		and target_4.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_debug_print_msg")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="bad server key exchange message"
}

predicate func_6(Variable vp_2269, Variable vend_2269, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vp_2269
		and target_6.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_2269
		and target_6.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="2"
}

predicate func_7(Variable vp_2269, Variable vsig_len_2429, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsig_len_2429
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_2269
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_2269
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_8(Variable vp_2269, Variable vsig_len_2429, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("mbedtls_debug_print_buf")
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vp_2269
		and target_8.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vsig_len_2429
}

from Function func, Variable vp_2269, Variable vend_2269, Variable vsig_len_2429, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, PointerArithmeticOperation target_4, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vend_2269, vsig_len_2429, target_5, target_6, target_7, target_8)
and func_1(vend_2269, target_5, target_1)
and func_2(vp_2269, target_2)
and func_3(vsig_len_2429, target_3)
and func_4(vp_2269, vend_2269, vsig_len_2429, target_5, target_4)
and func_5(target_5)
and func_6(vp_2269, vend_2269, target_6)
and func_7(vp_2269, vsig_len_2429, target_7)
and func_8(vp_2269, vsig_len_2429, target_8)
and vp_2269.getType().hasName("unsigned char *")
and vend_2269.getType().hasName("unsigned char *")
and vsig_len_2429.getType().hasName("size_t")
and vp_2269.getParentScope+() = func
and vend_2269.getParentScope+() = func
and vsig_len_2429.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
