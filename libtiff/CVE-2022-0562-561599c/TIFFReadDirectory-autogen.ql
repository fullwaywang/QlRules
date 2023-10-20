/**
 * @name libtiff-561599c99f987dc32ae110370cfdd7df7975586b-TIFFReadDirectory
 * @id cpp/libtiff/561599c99f987dc32ae110370cfdd7df7975586b/TIFFReadDirectory
 * @description libtiff-561599c99f987dc32ae110370cfdd7df7975586b-libtiff/tif_dirread.c-TIFFReadDirectory CVE-2022-0562
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vold_extrasamples_4160, LogicalAndExpr target_2, ExprStmt target_3, MulExpr target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vold_extrasamples_4160
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vold_extrasamples_4160, Variable vnew_sampleinfo_4161, Parameter vtif_3580, LogicalAndExpr target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew_sampleinfo_4161
		and target_1.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="td_sampleinfo"
		and target_1.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_1.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3580
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vold_extrasamples_4160
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="2"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vtif_3580, LogicalAndExpr target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="td_samplesperpixel"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3580
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="td_extrasamples"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3580
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Variable vold_extrasamples_4160, Parameter vtif_3580, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vold_extrasamples_4160
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="td_extrasamples"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3580
}

predicate func_4(Variable vold_extrasamples_4160, MulExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vold_extrasamples_4160
		and target_4.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getRightOperand().(SizeofTypeOperator).getValue()="2"
}

from Function func, Variable vold_extrasamples_4160, Variable vnew_sampleinfo_4161, Parameter vtif_3580, ExprStmt target_1, LogicalAndExpr target_2, ExprStmt target_3, MulExpr target_4
where
not func_0(vold_extrasamples_4160, target_2, target_3, target_4)
and func_1(vold_extrasamples_4160, vnew_sampleinfo_4161, vtif_3580, target_2, target_1)
and func_2(vtif_3580, target_2)
and func_3(vold_extrasamples_4160, vtif_3580, target_3)
and func_4(vold_extrasamples_4160, target_4)
and vold_extrasamples_4160.getType().hasName("uint16_t")
and vnew_sampleinfo_4161.getType().hasName("uint16_t *")
and vtif_3580.getType().hasName("TIFF *")
and vold_extrasamples_4160.(LocalVariable).getFunction() = func
and vnew_sampleinfo_4161.(LocalVariable).getFunction() = func
and vtif_3580.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
