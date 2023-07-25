/**
 * @name libtiff-54ce8c522078cd0f39861df71db848648ec28ade-_TIFFCheckFieldIsValidForCodec
 * @id cpp/libtiff/54ce8c522078cd0f39861df71db848648ec28ade/-TIFFCheckFieldIsValidForCodec
 * @description libtiff-54ce8c522078cd0f39861df71db848648ec28ade-libtiff/tif_dirinfo.c-_TIFFCheckFieldIsValidForCodec CVE-2020-19143
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SwitchCase target_0) {
		target_0.getExpr().(Literal).getValue()="50001"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vtag_1132, ValueFieldAccess target_3, EqualityOperation target_4, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtag_1132
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="317"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
}

predicate func_2(ValueFieldAccess target_3, Function func, BreakStmt target_2) {
		target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_2.getEnclosingFunction() = func
}

predicate func_3(ValueFieldAccess target_3) {
		target_3.getTarget().getName()="td_compression"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFF *")
}

predicate func_4(Parameter vtag_1132, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vtag_1132
		and target_4.getAnOperand().(Literal).getValue()="50674"
}

from Function func, Parameter vtag_1132, SwitchCase target_0, IfStmt target_1, BreakStmt target_2, ValueFieldAccess target_3, EqualityOperation target_4
where
func_0(func, target_0)
and func_1(vtag_1132, target_3, target_4, target_1)
and func_2(target_3, func, target_2)
and func_3(target_3)
and func_4(vtag_1132, target_4)
and vtag_1132.getType().hasName("ttag_t")
and vtag_1132.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
