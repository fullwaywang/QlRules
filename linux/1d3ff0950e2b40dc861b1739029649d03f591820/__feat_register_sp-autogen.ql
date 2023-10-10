/**
 * @name linux-1d3ff0950e2b40dc861b1739029649d03f591820-__feat_register_sp
 * @id cpp/linux/1d3ff0950e2b40dc861b1739029649d03f591820/__feat_register_sp
 * @description linux-1d3ff0950e2b40dc861b1739029649d03f591820-__feat_register_sp 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vfval_728, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition() instanceof FunctionCall
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="vec"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="sp"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vfval_728
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vmandatory_726, Variable vfval_728, Parameter vfn_725, Parameter vfeat_725, Parameter vis_local_725) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("dccp_feat_push_change")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vfn_725
		and target_4.getArgument(1).(VariableAccess).getTarget()=vfeat_725
		and target_4.getArgument(2).(VariableAccess).getTarget()=vis_local_725
		and target_4.getArgument(3).(VariableAccess).getTarget()=vmandatory_726
		and target_4.getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vfval_728)
}

from Function func, Parameter vmandatory_726, Variable vfval_728, Parameter vfn_725, Parameter vfeat_725, Parameter vis_local_725
where
not func_0(vfval_728, func)
and not func_3(func)
and func_4(vmandatory_726, vfval_728, vfn_725, vfeat_725, vis_local_725)
and vmandatory_726.getType().hasName("u8")
and vfval_728.getType().hasName("dccp_feat_val")
and vfn_725.getType().hasName("list_head *")
and vfeat_725.getType().hasName("u8")
and vis_local_725.getType().hasName("u8")
and vmandatory_726.getParentScope+() = func
and vfval_728.getParentScope+() = func
and vfn_725.getParentScope+() = func
and vfeat_725.getParentScope+() = func
and vis_local_725.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
