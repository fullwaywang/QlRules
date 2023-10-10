/**
 * @name linux-0f886ca12765d20124bd06291c82951fd49a33be-create_fixed_stream_quirk
 * @id cpp/linux/0f886ca12765d20124bd06291c82951fd49a33be/create_fixed_stream_quirk
 * @description linux-0f886ca12765d20124bd06291c82951fd49a33be-create_fixed_stream_quirk 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vfp_142, Variable valtsd_144, Variable vrate_table_146, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valtsd_144
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_142
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrate_table_146
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0))
}

predicate func_4(Variable vfp_142) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="altset_idx"
		and target_4.getQualifier().(VariableAccess).getTarget()=vfp_142)
}

predicate func_5(Variable valts_143, Variable valtsd_144) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=valtsd_144
		and target_5.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="desc"
		and target_5.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valts_143)
}

predicate func_6(Variable vrate_table_146) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("kfree")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vrate_table_146)
}

from Function func, Variable vfp_142, Variable valts_143, Variable valtsd_144, Variable vrate_table_146
where
not func_0(vfp_142, valtsd_144, vrate_table_146, func)
and vfp_142.getType().hasName("audioformat *")
and func_4(vfp_142)
and valtsd_144.getType().hasName("usb_interface_descriptor *")
and func_5(valts_143, valtsd_144)
and vrate_table_146.getType().hasName("unsigned int *")
and func_6(vrate_table_146)
and vfp_142.getParentScope+() = func
and valts_143.getParentScope+() = func
and valtsd_144.getParentScope+() = func
and vrate_table_146.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
