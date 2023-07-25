/**
 * @name e2fsprogs-8dd73c149f418238f19791f9d666089ef9734dff-fill_dir_block
 * @id cpp/e2fsprogs/8dd73c149f418238f19791f9d666089ef9734dff/fill-dir-block
 * @description e2fsprogs-8dd73c149f418238f19791f9d666089ef9734dff-e2fsck/rehash.c-fill_dir_block CVE-2019-5188
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfd_111, Variable vname_len_115, ExprStmt target_1, LogicalAndExpr target_2, LogicalOrExpr target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vname_len_115
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="err"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfd_111
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2133571363"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="2"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vfd_111, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="err"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfd_111
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2133571363"
}

predicate func_2(Variable vfd_111, Variable vname_len_115, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="compress"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfd_111
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vname_len_115
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="46"
}

predicate func_3(Variable vname_len_115, LogicalOrExpr target_3) {
		target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="blocksize"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(RemExpr).getRightOperand().(Literal).getValue()="4"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vname_len_115
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="8"
}

from Function func, Variable vfd_111, Variable vname_len_115, ExprStmt target_1, LogicalAndExpr target_2, LogicalOrExpr target_3
where
not func_0(vfd_111, vname_len_115, target_1, target_2, target_3)
and func_1(vfd_111, target_1)
and func_2(vfd_111, vname_len_115, target_2)
and func_3(vname_len_115, target_3)
and vfd_111.getType().hasName("fill_dir_struct *")
and vname_len_115.getType().hasName("unsigned int")
and vfd_111.getParentScope+() = func
and vname_len_115.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
