/**
 * @name libtiff-1044b43637fa7f70fb19b93593777b78bd20da86-PixarLogClose
 * @id cpp/libtiff/1044b43637fa7f70fb19b93593777b78bd20da86/PixarLogClose
 * @description libtiff-1044b43637fa7f70fb19b93593777b78bd20da86-libtiff/tif_pixarlog.c-PixarLogClose CVE-2016-10269
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(CommaExpr).getLeftOperand().(SizeofExprOperator).getValue()="4"
		and target_0.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("PixarLogState *")
		and target_0.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__assert_fail")
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("PixarLogState *")
		and target_1.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1))
}

predicate func_2(Variable vtd_1236, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="td_bitspersample"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1236
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vtd_1236, Function func, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="td_sampleformat"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1236
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

from Function func, Variable vtd_1236, ExprStmt target_2, ExprStmt target_3
where
not func_0(func)
and not func_1(func)
and func_2(vtd_1236, func, target_2)
and func_3(vtd_1236, func, target_3)
and vtd_1236.getType().hasName("TIFFDirectory *")
and vtd_1236.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
