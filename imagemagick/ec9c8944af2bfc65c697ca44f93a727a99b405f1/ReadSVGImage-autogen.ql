/**
 * @name imagemagick-ec9c8944af2bfc65c697ca44f93a727a99b405f1-ReadSVGImage
 * @id cpp/imagemagick/ec9c8944af2bfc65c697ca44f93a727a99b405f1/ReadSVGImage
 * @description imagemagick-ec9c8944af2bfc65c697ca44f93a727a99b405f1-coders/svg.c-ReadSVGImage CVE-2019-18853
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_info_3182, RelationalOperation target_3, ExprStmt target_4, EqualityOperation target_5) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const char *")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetImageOption")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_info_3182
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="svg:xml-parse-huge"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(RelationalOperation target_3, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("const char *")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("IsStringTrue")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const char *")
		and target_1.getThen() instanceof ExprStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vsvg_info_3202, RelationalOperation target_3, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("xmlCtxtUseOptions")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parser"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3202
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vsvg_info_3202, Parameter vimage_info_3182, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("CloneString")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3202
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_3182
}

predicate func_5(Parameter vimage_info_3182, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="ping"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_3182
}

from Function func, Variable vsvg_info_3202, Parameter vimage_info_3182, ExprStmt target_2, RelationalOperation target_3, ExprStmt target_4, EqualityOperation target_5
where
not func_0(vimage_info_3182, target_3, target_4, target_5)
and not func_1(target_3, func)
and func_2(vsvg_info_3202, target_3, target_2)
and func_3(target_3)
and func_4(vsvg_info_3202, vimage_info_3182, target_4)
and func_5(vimage_info_3182, target_5)
and vsvg_info_3202.getType().hasName("SVGInfo *")
and vimage_info_3182.getType().hasName("const ImageInfo *")
and vsvg_info_3202.getParentScope+() = func
and vimage_info_3182.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
