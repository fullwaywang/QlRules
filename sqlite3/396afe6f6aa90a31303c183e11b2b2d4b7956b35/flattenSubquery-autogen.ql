/**
 * @name sqlite3-396afe6f6aa90a31303c183e11b2b2d4b7956b35-flattenSubquery
 * @id cpp/sqlite3/396afe6f6aa90a31303c183e11b2b2d4b7956b35/flattenSubquery
 * @description sqlite3-396afe6f6aa90a31303c183e11b2b2d4b7956b35-src/select.c-flattenSubquery CVE-2019-19923
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_3714, BlockStmt target_2, LogicalAndExpr target_3, LogicalOrExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="selFlags"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_3714
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter visAgg_3716, Variable vpSubSrc_3723, BlockStmt target_2, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="nSrc"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSubSrc_3723
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=visAgg_3716
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="nModuleArg"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="a"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSubSrc_3723
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_3(Parameter vp_3714, LogicalAndExpr target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="pLimit"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Select *")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="selFlags"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_3714
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Parameter vp_3714, Parameter visAgg_3716, LogicalOrExpr target_4) {
		target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=visAgg_3716
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="selFlags"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_3714
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nSrc"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("SrcList *")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

from Function func, Parameter vp_3714, Parameter visAgg_3716, Variable vpSubSrc_3723, LogicalOrExpr target_1, BlockStmt target_2, LogicalAndExpr target_3, LogicalOrExpr target_4
where
not func_0(vp_3714, target_2, target_3, target_4)
and func_1(visAgg_3716, vpSubSrc_3723, target_2, target_1)
and func_2(target_2)
and func_3(vp_3714, target_3)
and func_4(vp_3714, visAgg_3716, target_4)
and vp_3714.getType().hasName("Select *")
and visAgg_3716.getType().hasName("int")
and vpSubSrc_3723.getType().hasName("SrcList *")
and vp_3714.getFunction() = func
and visAgg_3716.getFunction() = func
and vpSubSrc_3723.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
