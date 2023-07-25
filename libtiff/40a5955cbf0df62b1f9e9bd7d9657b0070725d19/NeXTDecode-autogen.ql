/**
 * @name libtiff-40a5955cbf0df62b1f9e9bd7d9657b0070725d19-NeXTDecode
 * @id cpp/libtiff/40a5955cbf0df62b1f9e9bd7d9657b0070725d19/NeXTDecode
 * @description libtiff-40a5955cbf0df62b1f9e9bd7d9657b0070725d19-libtiff/tif_next.c-NeXTDecode CVE-2014-9655
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcc_53, BlockStmt target_3, ExprStmt target_4, ExprStmt target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcc_53
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(ForStmt).getStmt()=target_3
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(CommaExpr).getRightOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcc_53, ExprStmt target_6, LogicalOrExpr target_7) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcc_53
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_6.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vocc_49, BlockStmt target_3, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vocc_49
		and target_2.getLesserOperand().(Literal).getValue()="0"
		and target_2.getParent().(ForStmt).getStmt()=target_3
}

predicate func_3(Variable vcc_53, BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_3.getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_3.getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vcc_53
		and target_3.getStmt(1).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_3.getStmt(1).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="0"
		and target_3.getStmt(1).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcc_53
		and target_3.getStmt(1).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_3.getStmt(1).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_3.getStmt(1).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("uint8 *")
		and target_3.getStmt(1).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_3.getStmt(1).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("tmsize_t")
}

predicate func_4(Variable vcc_53, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcc_53
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tif_rawcc"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFF *")
}

predicate func_5(Variable vcc_53, ExprStmt target_5) {
		target_5.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_5.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_5.getExpr().(CommaExpr).getRightOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vcc_53
}

predicate func_6(Variable vcc_53, ExprStmt target_6) {
		target_6.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vcc_53
		and target_6.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
}

predicate func_7(Variable vcc_53, LogicalOrExpr target_7) {
		target_7.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcc_53
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_7.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
}

from Function func, Parameter vocc_49, Variable vcc_53, RelationalOperation target_2, BlockStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, LogicalOrExpr target_7
where
not func_0(vcc_53, target_3, target_4, target_5)
and not func_1(vcc_53, target_6, target_7)
and func_2(vocc_49, target_3, target_2)
and func_3(vcc_53, target_3)
and func_4(vcc_53, target_4)
and func_5(vcc_53, target_5)
and func_6(vcc_53, target_6)
and func_7(vcc_53, target_7)
and vocc_49.getType().hasName("tmsize_t")
and vcc_53.getType().hasName("tmsize_t")
and vocc_49.getFunction() = func
and vcc_53.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
