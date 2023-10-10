/**
 * @name gnutls-75a937d97f4fefc6f9b08e3791f151445f551cb3-client_send_params
 * @id cpp/gnutls/75a937d97f4fefc6f9b08e3791f151445f551cb3/client-send-params
 * @description gnutls-75a937d97f4fefc6f9b08e3791f151445f551cb3-client_send_params CVE-2021-20232
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable v__func__) {
	exists(Literal target_0 |
		target_0.getValue()="448"
		and not target_0.getValue()="452"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_gnutls_log")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ASSERT: %s[%s]:%d\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pre_shared_key.c"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__)
}

predicate func_1(Variable v__func__) {
	exists(Literal target_1 |
		target_1.getValue()="469"
		and not target_1.getValue()="473"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_gnutls_log")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ASSERT: %s[%s]:%d\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pre_shared_key.c"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__)
}

predicate func_2(Variable v__func__) {
	exists(Literal target_2 |
		target_2.getValue()="482"
		and not target_2.getValue()="491"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_gnutls_log")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ASSERT: %s[%s]:%d\n"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pre_shared_key.c"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__)
}

predicate func_3(Variable v__func__) {
	exists(Literal target_3 |
		target_3.getValue()="503"
		and not target_3.getValue()="512"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_gnutls_log")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ASSERT: %s[%s]:%d\n"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pre_shared_key.c"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof IntType
		and func.getEntryPoint().(BlockStmt).getStmt(5)=target_4)
}

predicate func_6(Variable vrkey_269, Variable vprf_res_272) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue() instanceof ValueFieldAccess
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("unsigned int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vprf_res_272
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrkey_269
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0")
}

predicate func_7(Variable vuser_key_269, Variable vprf_psk_273, Variable vinfo_277) {
	exists(DeclStmt target_7 |
		target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vprf_psk_273
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vuser_key_269
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vinfo_277)
}

predicate func_8(Parameter vextdata_262, Variable vuser_key_269, Variable vprf_psk_273, Variable vinfo_277) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("gnutls_datum_t")
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vextdata_262
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="80"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vprf_psk_273
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vuser_key_269
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vinfo_277)
}

predicate func_12(Variable vclient_hello_270) {
	exists(ValueFieldAccess target_12 |
		target_12.getTarget().getName()="size"
		and target_12.getQualifier().(VariableAccess).getTarget()=vclient_hello_270)
}

predicate func_13(Parameter vextdata_262, Variable vbinder_value_266, Variable vprf_res_272) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("_gnutls_buffer_append_data_prefix")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vextdata_262
		and target_13.getArgument(1).(Literal).getValue()="8"
		and target_13.getArgument(2).(VariableAccess).getTarget()=vbinder_value_266
		and target_13.getArgument(3).(PointerFieldAccess).getTarget().getName()="output_size"
		and target_13.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprf_res_272)
}

from Function func, Parameter vextdata_262, Variable vbinder_value_266, Variable vuser_key_269, Variable vrkey_269, Variable vclient_hello_270, Variable vprf_res_272, Variable vprf_psk_273, Variable vinfo_277, Variable v__func__
where
func_0(v__func__)
and func_1(v__func__)
and func_2(v__func__)
and func_3(v__func__)
and not func_4(func)
and not func_6(vrkey_269, vprf_res_272)
and not func_7(vuser_key_269, vprf_psk_273, vinfo_277)
and not func_8(vextdata_262, vuser_key_269, vprf_psk_273, vinfo_277)
and func_12(vclient_hello_270)
and vextdata_262.getType().hasName("gnutls_buffer_t")
and func_13(vextdata_262, vbinder_value_266, vprf_res_272)
and vbinder_value_266.getType().hasName("uint8_t[64]")
and vuser_key_269.getType().hasName("gnutls_datum_t")
and vrkey_269.getType().hasName("gnutls_datum_t")
and vclient_hello_270.getType().hasName("gnutls_datum_t")
and vprf_res_272.getType().hasName("const mac_entry_st *")
and vprf_psk_273.getType().hasName("const mac_entry_st *")
and vinfo_277.getType().hasName("psk_auth_info_t")
and v__func__.getType().hasName("const char[19]")
and vextdata_262.getParentScope+() = func
and vbinder_value_266.getParentScope+() = func
and vuser_key_269.getParentScope+() = func
and vrkey_269.getParentScope+() = func
and vclient_hello_270.getParentScope+() = func
and vprf_res_272.getParentScope+() = func
and vprf_psk_273.getParentScope+() = func
and vinfo_277.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
