/**
 * @name wireshark-28a7a79cac425d1b1ecf06e73add41edd2241e49-parseDiagnosticInfo
 * @id cpp/wireshark/28a7a79cac425d1b1ecf06e73add41edd2241e49/parseDiagnosticInfo
 * @description wireshark-28a7a79cac425d1b1ecf06e73add41edd2241e49-plugins/epan/opcua/opcua_simpletypes.c-parseDiagnosticInfo CVE-2018-12086
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpinfo_790, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("guint")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("p_get_proto_data")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_790
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_790
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vpinfo_790, Variable vti_804, AddressOfExpr target_5, ExprStmt target_6, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PrefixIncrExpr).getOperand().(VariableAccess).getType().hasName("guint")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="100"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_790
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vti_804
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpinfo_790, ExprStmt target_7, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("p_add_proto_data")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_790
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_790
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("guint")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_2)
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_4(Function func, ReturnStmt target_4) {
		target_4.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vti_804, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vti_804
}

predicate func_6(Variable vti_804, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("proto_item_set_end")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vti_804
}

predicate func_7(Parameter vpinfo_790, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("parseInt32")
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpinfo_790
}

from Function func, Parameter vpinfo_790, Variable vti_804, ReturnStmt target_4, AddressOfExpr target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vpinfo_790, func)
and not func_1(vpinfo_790, vti_804, target_5, target_6, func)
and not func_2(vpinfo_790, target_7, func)
and func_4(func, target_4)
and func_5(vti_804, target_5)
and func_6(vti_804, target_6)
and func_7(vpinfo_790, target_7)
and vpinfo_790.getType().hasName("packet_info *")
and vti_804.getType().hasName("proto_item *")
and vpinfo_790.getParentScope+() = func
and vti_804.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
