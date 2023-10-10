/**
 * @name libtiff-24a2eee78bb057acb2c3992acd002654c1747718-gtStripContig
 * @id cpp/libtiff/24a2eee78bb057acb2c3992acd002654c1747718/gtStripContig
 * @description libtiff-24a2eee78bb057acb2c3992acd002654c1747718-libtiff/tif_getimage.c-gtStripContig CVE-2014-9655
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtif_848, Variable vsubsamplingver_854, ExprStmt target_1, ExprStmt target_2, AddressOfExpr target_3, EqualityOperation target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsubsamplingver_854
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_848
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_848
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid vertical YCbCr subsampling"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtif_848, Variable vsubsamplingver_854, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("TIFFGetFieldDefaulted")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_848
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="530"
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint16")
		and target_1.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsubsamplingver_854
}

predicate func_2(Variable vtif_848, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFScanlineSize")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_848
}

predicate func_3(Variable vsubsamplingver_854, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vsubsamplingver_854
}

predicate func_4(Variable vsubsamplingver_854, EqualityOperation target_4) {
		target_4.getAnOperand().(RemExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_4.getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getTarget()=vsubsamplingver_854
		and target_4.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vtif_848, Variable vsubsamplingver_854, ExprStmt target_1, ExprStmt target_2, AddressOfExpr target_3, EqualityOperation target_4
where
not func_0(vtif_848, vsubsamplingver_854, target_1, target_2, target_3, target_4, func)
and func_1(vtif_848, vsubsamplingver_854, target_1)
and func_2(vtif_848, target_2)
and func_3(vsubsamplingver_854, target_3)
and func_4(vsubsamplingver_854, target_4)
and vtif_848.getType().hasName("TIFF *")
and vsubsamplingver_854.getType().hasName("uint16")
and vtif_848.(LocalVariable).getFunction() = func
and vsubsamplingver_854.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
