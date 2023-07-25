/**
 * @name openjpeg-ad593c9e0622e0d8d87228e67e4dbd36243ffd22-color_esycc_to_rgb
 * @id cpp/openjpeg/ad593c9e0622e0d8d87228e67e4dbd36243ffd22/color-esycc-to-rgb
 * @description openjpeg-ad593c9e0622e0d8d87228e67e4dbd36243ffd22-src/bin/common/color.c-color_esycc_to_rgb CVE-2016-1923
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_886, ReturnStmt target_4, RelationalOperation target_2) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dx"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dx"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dx"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dx"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_886
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_886
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_886
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dy"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_886
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(RelationalOperation target_2, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("FILE *")
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s:%d:color_esycc_to_rgb\n\tCAN NOT CONVERT\n"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="/opt/project/build/cloned/openjpeg/src/bin/common/color.c"
		and target_1.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="898"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vimage_886, ReturnStmt target_4, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="numcomps"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_886
		and target_2.getGreaterOperand().(Literal).getValue()="3"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Function func, ReturnStmt target_3) {
		target_3.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(RelationalOperation target_2, Function func, ReturnStmt target_4) {
		target_4.toString() = "return ..."
		and target_4.getParent().(IfStmt).getCondition()=target_2
		and target_4.getEnclosingFunction() = func
}

from Function func, Parameter vimage_886, RelationalOperation target_2, ReturnStmt target_3, ReturnStmt target_4
where
not func_0(vimage_886, target_4, target_2)
and not func_1(target_2, func)
and func_2(vimage_886, target_4, target_2)
and func_3(func, target_3)
and func_4(target_2, func, target_4)
and vimage_886.getType().hasName("opj_image_t *")
and vimage_886.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
