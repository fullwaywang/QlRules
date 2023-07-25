/**
 * @name libtiff-3144e57770c1e4d26520d8abee750f8ac8b75490-TIFFReadDirEntryFloatArray
 * @id cpp/libtiff/3144e57770c1e4d26520d8abee750f8ac8b75490/TIFFReadDirEntryFloatArray
 * @description libtiff-3144e57770c1e4d26520d8abee750f8ac8b75490-libtiff/tif_dirread.c-TIFFReadDirEntryFloatArray CVE-2017-7597
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("double")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="3.402823466e+38"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("double")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3.402823466e+38"
		and target_0.getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("double")
		and target_0.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-3.402823466385288598e+38"
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("double")
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-3.402823466385288598e+38"
		and target_0.getEnclosingFunction() = func)
}

/*predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("double")
		and target_1.getRValue().(Literal).getValue()="3.402823466e+38"
		and target_1.getEnclosingFunction() = func)
}

*/
predicate func_2(Variable vmb_2401, ExprStmt target_5) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vmb_2401
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("double")
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vma_2400, Variable vmb_2401, PointerDereferenceExpr target_4) {
		target_4.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vma_2400
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vmb_2401
}

predicate func_5(Variable vmb_2401, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmb_2401
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("float *")
}

from Function func, Variable vma_2400, Variable vmb_2401, PointerDereferenceExpr target_4, ExprStmt target_5
where
not func_0(func)
and not func_2(vmb_2401, target_5)
and func_4(vma_2400, vmb_2401, target_4)
and func_5(vmb_2401, target_5)
and vma_2400.getType().hasName("double *")
and vmb_2401.getType().hasName("float *")
and vma_2400.(LocalVariable).getFunction() = func
and vmb_2401.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
