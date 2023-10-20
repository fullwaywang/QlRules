/**
 * @name openssl-86f8fb0e344d62454f8daf3e15236b2b59210756-get_client_master_key
 * @id cpp/openssl/86f8fb0e344d62454f8daf3e15236b2b59210756/get-client-master-key
 * @description openssl-86f8fb0e344d62454f8daf3e15236b2b59210756-get_client_master_key CVE-2015-0293
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_374) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vi_374)
}

predicate func_7(Variable vis_export_374, Variable vek_374) {
	exists(ReturnStmt target_7 |
		target_7.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_export_374
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="enc"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vek_374
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vis_export_374
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="enc"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length"))
}

predicate func_12(Variable vis_export_374, Variable vi_374, Variable vc_378, Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(VariableAccess).getTarget()=vis_export_374
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_374
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length")
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_378
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_12))
}

predicate func_18(Parameter vs_372) {
	exists(ValueFieldAccess target_18 |
		target_18.getTarget().getName()="clear"
		and target_18.getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s2"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372)
}

predicate func_25(Variable vi_374) {
	exists(AssignAddExpr target_25 |
		target_25.getLValue().(VariableAccess).getTarget()=vi_374
		and target_25.getRValue() instanceof ValueFieldAccess)
}

predicate func_26(Parameter vs_372) {
	exists(PointerFieldAccess target_26 |
		target_26.getTarget().getName()="cipher"
		and target_26.getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_26.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372)
}

predicate func_27(Parameter vs_372) {
	exists(PointerFieldAccess target_27 |
		target_27.getTarget().getName()="tmp"
		and target_27.getQualifier().(PointerFieldAccess).getTarget().getName()="s2"
		and target_27.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372)
}

predicate func_29(Variable vis_export_374) {
	exists(AssignExpr target_29 |
		target_29.getLValue().(VariableAccess).getTarget()=vis_export_374
		and target_29.getRValue().(Literal).getValue()="1")
}

predicate func_30(Variable vis_export_374, Variable vi_374, Variable vp_376, Variable vc_378) {
	exists(LogicalOrExpr target_30 |
		target_30.getAnOperand() instanceof RelationalOperation
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vis_export_374
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_374
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_378
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_export_374
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand() instanceof ValueFieldAccess
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_374
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_378
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("RAND_pseudo_bytes")
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_376
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vi_374
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_32(Variable vek_374) {
	exists(AssignExpr target_32 |
		target_32.getLValue().(VariableAccess).getTarget()=vek_374
		and target_32.getRValue().(Literal).getValue()="5")
}

predicate func_34(Variable vi_374, Variable vc_378) {
	exists(AssignExpr target_34 |
		target_34.getLValue().(VariableAccess).getTarget()=vi_374
		and target_34.getRValue().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length")
		and target_34.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_378)
}

from Function func, Parameter vs_372, Variable vis_export_374, Variable vi_374, Variable vek_374, Variable vp_376, Variable vc_378
where
func_0(vi_374)
and not func_7(vis_export_374, vek_374)
and not func_12(vis_export_374, vi_374, vc_378, func)
and func_18(vs_372)
and func_25(vi_374)
and vs_372.getType().hasName("SSL *")
and func_26(vs_372)
and func_27(vs_372)
and vis_export_374.getType().hasName("int")
and func_29(vis_export_374)
and func_30(vis_export_374, vi_374, vp_376, vc_378)
and vi_374.getType().hasName("int")
and vek_374.getType().hasName("int")
and func_32(vek_374)
and vp_376.getType().hasName("unsigned char *")
and vc_378.getType().hasName("const EVP_CIPHER *")
and func_34(vi_374, vc_378)
and vs_372.getParentScope+() = func
and vis_export_374.getParentScope+() = func
and vi_374.getParentScope+() = func
and vek_374.getParentScope+() = func
and vp_376.getParentScope+() = func
and vc_378.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
