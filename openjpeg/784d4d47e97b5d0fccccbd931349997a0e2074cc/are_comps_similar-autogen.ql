/**
 * @name openjpeg-784d4d47e97b5d0fccccbd931349997a0e2074cc-are_comps_similar
 * @id cpp/openjpeg/784d4d47e97b5d0fccccbd931349997a0e2074cc/are-comps-similar
 * @description openjpeg-784d4d47e97b5d0fccccbd931349997a0e2074cc-src/bin/jp2/convert.c-are_comps_similar CVE-2016-9114
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_1893, Variable vi_1895, BlockStmt target_3, ArrayExpr target_4, ArrayExpr target_5, ArrayExpr target_6) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1895
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1895
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1895
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_3
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vimage_1893, Variable vi_1895, LogicalOrExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dx"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dx"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1895
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1895
}

*/
predicate func_2(Parameter vimage_1893, Variable vi_1895, BlockStmt target_3, EqualityOperation target_2) {
		target_2.getAnOperand().(ValueFieldAccess).getTarget().getName()="sgnd"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getAnOperand().(ValueFieldAccess).getTarget().getName()="sgnd"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1895
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dx"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dx"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1895
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(BlockStmt target_3) {
		target_3.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_4(Parameter vimage_1893, Variable vi_1895, ArrayExpr target_4) {
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_4.getArrayOffset().(VariableAccess).getTarget()=vi_1895
}

predicate func_5(Parameter vimage_1893, ArrayExpr target_5) {
		target_5.getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_5.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_5.getArrayOffset().(Literal).getValue()="0"
}

predicate func_6(Parameter vimage_1893, Variable vi_1895, ArrayExpr target_6) {
		target_6.getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1893
		and target_6.getArrayOffset().(VariableAccess).getTarget()=vi_1895
}

from Function func, Parameter vimage_1893, Variable vi_1895, EqualityOperation target_2, BlockStmt target_3, ArrayExpr target_4, ArrayExpr target_5, ArrayExpr target_6
where
not func_0(vimage_1893, vi_1895, target_3, target_4, target_5, target_6)
and func_2(vimage_1893, vi_1895, target_3, target_2)
and func_3(target_3)
and func_4(vimage_1893, vi_1895, target_4)
and func_5(vimage_1893, target_5)
and func_6(vimage_1893, vi_1895, target_6)
and vimage_1893.getType().hasName("opj_image_t *")
and vi_1895.getType().hasName("unsigned int")
and vimage_1893.getParentScope+() = func
and vi_1895.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
