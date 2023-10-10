/**
 * @name libtiff-4d4fa0b68ae9ae038959ee4f69ebe288ec892f06-TIFFReadDirectory
 * @id cpp/libtiff/4d4fa0b68ae9ae038959ee4f69ebe288ec892f06/TIFFReadDirectory
 * @description libtiff-4d4fa0b68ae9ae038959ee4f69ebe288ec892f06-libtiff/tif_dirread.c-TIFFReadDirectory CVE-2015-7554
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vdp_3418, Parameter vtif_3413, PointerFieldAccess target_3, ExprStmt target_4, NotExpr target_5, LogicalAndExpr target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_TIFFCheckFieldIsValidForCodec")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3413
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_3418
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_3418
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(PointerFieldAccess target_3, Function func) {
	exists(BreakStmt target_2 |
		target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vdp_3418, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="tdir_tag"
		and target_3.getQualifier().(VariableAccess).getTarget()=vdp_3418
}

predicate func_4(Variable vdp_3418, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_3418
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_5(Variable vdp_3418, Parameter vtif_3413, NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("TIFFFetchNormalTag")
		and target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3413
		and target_5.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdp_3418
		and target_5.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_6(Parameter vtif_3413, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="td_compression"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="6"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="td_planarconfig"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
}

from Function func, Variable vdp_3418, Parameter vtif_3413, PointerFieldAccess target_3, ExprStmt target_4, NotExpr target_5, LogicalAndExpr target_6
where
not func_1(vdp_3418, vtif_3413, target_3, target_4, target_5, target_6)
and not func_2(target_3, func)
and func_3(vdp_3418, target_3)
and func_4(vdp_3418, target_4)
and func_5(vdp_3418, vtif_3413, target_5)
and func_6(vtif_3413, target_6)
and vdp_3418.getType().hasName("TIFFDirEntry *")
and vtif_3413.getType().hasName("TIFF *")
and vdp_3418.(LocalVariable).getFunction() = func
and vtif_3413.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
