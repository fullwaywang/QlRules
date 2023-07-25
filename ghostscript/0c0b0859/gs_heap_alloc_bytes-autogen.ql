/**
 * @name ghostscript-0c0b0859-gs_heap_alloc_bytes
 * @id cpp/ghostscript/0c0b0859/gs-heap-alloc-bytes
 * @description ghostscript-0c0b0859-gs/base/gsmalloc.c-gs_heap_alloc_bytes CVE-2015-3228
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_158, Variable vadded_179, DoStmt target_2, AddExpr target_3, ExprStmt target_4, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vadded_179
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_158
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vmmem_160, Variable vadded_179, DoStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="limit"
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmem_160
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vadded_179
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="used"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmem_160
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(DoStmt target_2) {
		target_2.getCondition().(Literal).getValue()="0"
}

predicate func_3(Parameter vsize_158, AddExpr target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vsize_158
		and target_3.getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getAnOperand().(SizeofTypeOperator).getValue()="48"
}

predicate func_4(Parameter vsize_158, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gs_malloc_block_t *")
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsize_158
}

from Function func, Parameter vsize_158, Variable vmmem_160, Variable vadded_179, RelationalOperation target_1, DoStmt target_2, AddExpr target_3, ExprStmt target_4
where
not func_0(vsize_158, vadded_179, target_2, target_3, target_4, target_1)
and func_1(vmmem_160, vadded_179, target_2, target_1)
and func_2(target_2)
and func_3(vsize_158, target_3)
and func_4(vsize_158, target_4)
and vsize_158.getType().hasName("uint")
and vmmem_160.getType().hasName("gs_malloc_memory_t *")
and vadded_179.getType().hasName("uint")
and vsize_158.getFunction() = func
and vmmem_160.(LocalVariable).getFunction() = func
and vadded_179.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
