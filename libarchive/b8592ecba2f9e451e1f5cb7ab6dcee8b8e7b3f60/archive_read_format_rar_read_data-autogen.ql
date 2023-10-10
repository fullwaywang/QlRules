/**
 * @name libarchive-b8592ecba2f9e451e1f5cb7ab6dcee8b8e7b3f60-archive_read_format_rar_read_data
 * @id cpp/libarchive/b8592ecba2f9e451e1f5cb7ab6dcee8b8e7b3f60/archive-read-format-rar-read-data
 * @description libarchive-b8592ecba2f9e451e1f5cb7ab6dcee8b8e7b3f60-libarchive/archive_read_support_format_rar.c-archive_read_format_rar_read_data CVE-2019-18408
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrar_993, LogicalAndExpr target_2, SwitchStmt target_3, AddressOfExpr target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="start_new_table"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrar_993
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrar_993, Variable v__archive_ppmd7_functions, LogicalAndExpr target_2, ExprStmt target_1) {
		target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="Ppmd7_Free"
		and target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=v__archive_ppmd7_functions
		and target_1.getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ppmd7_context"
		and target_1.getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrar_993
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-20"
}

predicate func_3(Variable vrar_993, SwitchStmt target_3) {
		target_3.getExpr().(PointerFieldAccess).getTarget().getName()="compression_method"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrar_993
		and target_3.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="48"
		and target_3.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("read_data_stored")
		and target_3.getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_3.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="49"
		and target_3.getStmt().(BlockStmt).getStmt(4).(SwitchCase).getExpr().(Literal).getValue()="50"
}

predicate func_4(Variable vrar_993, AddressOfExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="ppmd7_context"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrar_993
}

from Function func, Variable vrar_993, Variable v__archive_ppmd7_functions, ExprStmt target_1, LogicalAndExpr target_2, SwitchStmt target_3, AddressOfExpr target_4
where
not func_0(vrar_993, target_2, target_3, target_4)
and func_1(vrar_993, v__archive_ppmd7_functions, target_2, target_1)
and func_2(target_2)
and func_3(vrar_993, target_3)
and func_4(vrar_993, target_4)
and vrar_993.getType().hasName("rar *")
and v__archive_ppmd7_functions.getType().hasName("const IPpmd7")
and vrar_993.getParentScope+() = func
and not v__archive_ppmd7_functions.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
