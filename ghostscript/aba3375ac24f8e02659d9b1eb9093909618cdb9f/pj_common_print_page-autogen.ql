/**
 * @name ghostscript-aba3375ac24f8e02659d9b1eb9093909618cdb9f-pj_common_print_page
 * @id cpp/ghostscript/aba3375ac24f8e02659d9b1eb9093909618cdb9f/pj-common-print-page
 * @description ghostscript-aba3375ac24f8e02659d9b1eb9093909618cdb9f-devices/gdevpjet.c-pj_common_print_page CVE-2020-16288
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdata_105, ExprStmt target_1, PointerArithmeticOperation target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_105
		and target_0.getExpr().(FunctionCall).getArgument(1).(HexLiteral).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(MulExpr).getValue()="1536"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getExpr().(VariableCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdata_105, ExprStmt target_1) {
		target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free_object"
		and target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device_printer *")
		and target_1.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_1.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device_printer *")
		and target_1.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vdata_105
		and target_1.getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="paintjet_print_page(data)"
}

predicate func_2(Variable vdata_105, PointerArithmeticOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vdata_105
		and target_2.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vdata_105, ExprStmt target_1, PointerArithmeticOperation target_2
where
not func_0(vdata_105, target_1, target_2, func)
and func_1(vdata_105, target_1)
and func_2(vdata_105, target_2)
and vdata_105.getType().hasName("byte *")
and vdata_105.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
