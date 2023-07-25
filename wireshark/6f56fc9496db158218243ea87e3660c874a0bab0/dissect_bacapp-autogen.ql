/**
 * @name wireshark-6f56fc9496db158218243ea87e3660c874a0bab0-dissect_bacapp
 * @id cpp/wireshark/6f56fc9496db158218243ea87e3660c874a0bab0/dissect-bacapp
 * @description wireshark-6f56fc9496db158218243ea87e3660c874a0bab0-epan/dissectors/packet-bacapp.c-dissect_bacapp CVE-2020-11647
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpinfo_14075, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("p_add_proto_data")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_14075
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_14075
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpinfo_14075, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("col_add_fstr")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cinfo"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_14075
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%-16s"
		and target_1.getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("val_to_str_const")
		and target_1.getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(2).(StringLiteral).getValue()="# unknown APDU #"
}

predicate func_2(Parameter vpinfo_14075, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("col_append_fstr")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cinfo"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_14075
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s[%3u] "
		and target_2.getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("val_to_str_const")
}

from Function func, Parameter vpinfo_14075, ExprStmt target_1, ExprStmt target_2
where
not func_0(vpinfo_14075, target_1, target_2, func)
and func_1(vpinfo_14075, target_1)
and func_2(vpinfo_14075, target_2)
and vpinfo_14075.getType().hasName("packet_info *")
and vpinfo_14075.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
