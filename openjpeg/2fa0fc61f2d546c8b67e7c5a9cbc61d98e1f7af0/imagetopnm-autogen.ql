/**
 * @name openjpeg-2fa0fc61f2d546c8b67e7c5a9cbc61d98e1f7af0-imagetopnm
 * @id cpp/openjpeg/2fa0fc61f2d546c8b67e7c5a9cbc61d98e1f7af0/imagetopnm
 * @description openjpeg-2fa0fc61f2d546c8b67e7c5a9cbc61d98e1f7af0-src/bin/jp2/convert.c-imagetopnm CVE-2016-9114
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1910"
		and not target_0.getValue()="1925"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s:%d:imagetopnm\n\tprecision %d is larger than 16\n\t: refused.\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="/opt/project/build/cloned/openjpeg/src/bin/jp2/convert.c"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vimage_1893, ExprStmt target_15, ArrayExpr target_16) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("are_comps_similar")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vimage_1893
		and target_15.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation())
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_16.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vimage_1893, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="comps"
		and target_2.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_2.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_3(Parameter vimage_1893, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="comps"
		and target_3.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_3.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_4(Parameter vimage_1893, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="comps"
		and target_4.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_4.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_5(Parameter vimage_1893, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="comps"
		and target_5.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_5.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_6(Parameter vimage_1893, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="comps"
		and target_6.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_6.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_7(Parameter vimage_1893, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="comps"
		and target_7.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_7.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_8(Parameter vimage_1893, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="comps"
		and target_8.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_8.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_9(Parameter vimage_1893, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="comps"
		and target_9.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_9.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_10(Parameter vimage_1893, ArrayExpr target_10) {
		target_10.getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_10.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_10.getArrayOffset().(Literal).getValue()="0"
}

predicate func_11(Parameter vimage_1893, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="comps"
		and target_11.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_11.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_12(Parameter vimage_1893, ArrayExpr target_12) {
		target_12.getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_12.getArrayOffset().(Literal).getValue()="1"
}

predicate func_13(Parameter vimage_1893, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="comps"
		and target_13.getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_13.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_14(Variable vncomp_1898, Parameter vimage_1893, BlockStmt target_17, LogicalOrExpr target_14) {
		target_14.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vncomp_1898
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier() instanceof ArrayExpr
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier() instanceof ArrayExpr
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_14.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_17
}

predicate func_15(Variable vncomp_1898, Parameter vimage_1893, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vncomp_1898
		and target_15.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="numcomps"
		and target_15.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
}

predicate func_16(Parameter vimage_1893, ArrayExpr target_16) {
		target_16.getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_16.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_16.getArrayOffset() instanceof Literal
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fopen")
		and target_17.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="wb"
		and target_17.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_17.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ERROR -> failed to open %s for writing\n"
		and target_17.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
}

from Function func, Variable vncomp_1898, Parameter vimage_1893, Literal target_0, PointerFieldAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, PointerFieldAccess target_8, PointerFieldAccess target_9, ArrayExpr target_10, PointerFieldAccess target_11, ArrayExpr target_12, PointerFieldAccess target_13, LogicalOrExpr target_14, ExprStmt target_15, ArrayExpr target_16, BlockStmt target_17
where
func_0(func, target_0)
and not func_1(vimage_1893, target_15, target_16)
and func_2(vimage_1893, target_2)
and func_3(vimage_1893, target_3)
and func_4(vimage_1893, target_4)
and func_5(vimage_1893, target_5)
and func_6(vimage_1893, target_6)
and func_7(vimage_1893, target_7)
and func_8(vimage_1893, target_8)
and func_9(vimage_1893, target_9)
and func_10(vimage_1893, target_10)
and func_11(vimage_1893, target_11)
and func_12(vimage_1893, target_12)
and func_13(vimage_1893, target_13)
and func_14(vncomp_1898, vimage_1893, target_17, target_14)
and func_15(vncomp_1898, vimage_1893, target_15)
and func_16(vimage_1893, target_16)
and func_17(target_17)
and vncomp_1898.getType().hasName("unsigned int")
and vimage_1893.getType().hasName("opj_image_t *")
and vncomp_1898.getParentScope+() = func
and vimage_1893.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
