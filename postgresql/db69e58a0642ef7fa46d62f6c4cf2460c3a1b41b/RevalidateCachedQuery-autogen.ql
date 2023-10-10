/**
 * @name postgresql-db69e58a0642ef7fa46d62f6c4cf2460c3a1b41b-RevalidateCachedQuery
 * @id cpp/postgresql/db69e58a0642ef7fa46d62f6c4cf2460c3a1b41b/RevalidateCachedQuery
 * @description postgresql-db69e58a0642ef7fa46d62f6c4cf2460c3a1b41b-src/backend/utils/cache/plancache.c-RevalidateCachedQuery CVE-2016-2193
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(NEExpr).getParent().(NotExpr).getOperand() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(PointerFieldAccess target_2, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vplansource_551, BlockStmt target_7, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="is_valid"
		and target_2.getQualifier().(VariableAccess).getTarget()=vplansource_551
		and target_2.getParent().(IfStmt).getThen()=target_7
}

predicate func_3(Parameter vplansource_551, NotExpr target_5, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="planUserId"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vplansource_551
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetUserId")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_4(Variable vrow_security, Parameter vplansource_551, NotExpr target_5, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="row_security_env"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vplansource_551
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vrow_security
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_5(Parameter vplansource_551, BlockStmt target_8, NotExpr target_5) {
		target_5.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="planUserId"
		and target_5.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vplansource_551
		and target_5.getOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_5.getParent().(IfStmt).getThen()=target_8
}

predicate func_6(Parameter vplansource_551, Function func, IfStmt target_6) {
		target_6.getCondition().(PointerFieldAccess).getTarget().getName()="is_valid"
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vplansource_551
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("OverrideSearchPathMatchesCurrent")
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="search_path"
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vplansource_551
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_valid"
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="gplan"
		and target_6.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vplansource_551
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vplansource_551, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_7.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("OverrideSearchPathMatchesCurrent")
		and target_7.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="search_path"
		and target_7.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vplansource_551
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_valid"
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vplansource_551
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="gplan"
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vplansource_551
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_valid"
		and target_7.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_8(BlockStmt target_8) {
		target_8.getStmt(0) instanceof ExprStmt
		and target_8.getStmt(1) instanceof ExprStmt
}

from Function func, Variable vrow_security, Parameter vplansource_551, Literal target_0, PointerFieldAccess target_2, ExprStmt target_3, ExprStmt target_4, NotExpr target_5, IfStmt target_6, BlockStmt target_7, BlockStmt target_8
where
func_0(func, target_0)
and not func_1(target_2, func)
and func_2(vplansource_551, target_7, target_2)
and func_3(vplansource_551, target_5, target_3)
and func_4(vrow_security, vplansource_551, target_5, target_4)
and func_5(vplansource_551, target_8, target_5)
and func_6(vplansource_551, func, target_6)
and func_7(vplansource_551, target_7)
and func_8(target_8)
and vrow_security.getType().hasName("bool")
and vplansource_551.getType().hasName("CachedPlanSource *")
and not vrow_security.getParentScope+() = func
and vplansource_551.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
