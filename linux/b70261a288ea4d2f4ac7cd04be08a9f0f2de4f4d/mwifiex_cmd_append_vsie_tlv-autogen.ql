/**
 * @name linux-b70261a288ea4d2f4ac7cd04be08a9f0f2de4f4d-mwifiex_cmd_append_vsie_tlv
 * @id cpp/linux/b70261a288ea4d2f4ac7cd04be08a9f0f2de4f4d/mwifiex_cmd_append_vsie_tlv
 * @description linux-b70261a288ea4d2f4ac7cd04be08a9f0f2de4f4d-mwifiex_cmd_append_vsie_tlv 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vvsie_mask_2863, Variable vid_2865, Variable vvs_param_set_2866, Parameter vpriv_2862) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="len"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="header"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvs_param_set_2866
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_mwifiex_dbg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="adapter"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_2862
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid param length!\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="mask"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="vs_ie"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_2862
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vid_2865
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vvsie_mask_2863)
}

predicate func_3(Function func) {
	exists(LabelStmt target_3 |
		target_3.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_3))
}

predicate func_4(Variable vvs_param_set_2866) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="header"
		and target_4.getQualifier().(VariableAccess).getTarget()=vvs_param_set_2866)
}

predicate func_5(Parameter vpriv_2862) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="vs_ie"
		and target_5.getQualifier().(VariableAccess).getTarget()=vpriv_2862)
}

from Function func, Parameter vvsie_mask_2863, Variable vid_2865, Variable vvs_param_set_2866, Parameter vpriv_2862
where
not func_0(vvsie_mask_2863, vid_2865, vvs_param_set_2866, vpriv_2862)
and not func_3(func)
and vvsie_mask_2863.getType().hasName("u16")
and vid_2865.getType().hasName("int")
and vvs_param_set_2866.getType().hasName("mwifiex_ie_types_vendor_param_set *")
and func_4(vvs_param_set_2866)
and vpriv_2862.getType().hasName("mwifiex_private *")
and func_5(vpriv_2862)
and vvsie_mask_2863.getParentScope+() = func
and vid_2865.getParentScope+() = func
and vvs_param_set_2866.getParentScope+() = func
and vpriv_2862.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
