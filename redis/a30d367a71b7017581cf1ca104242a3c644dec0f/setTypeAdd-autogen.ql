/**
 * @name redis-a30d367a71b7017581cf1ca104242a3c644dec0f-setTypeAdd
 * @id cpp/redis/a30d367a71b7017581cf1ca104242a3c644dec0f/setTypeAdd
 * @description redis-a30d367a71b7017581cf1ca104242a3c644dec0f-src/t_set.c-setTypeAdd CVE-2021-32687
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(ExprStmt target_5, Function func) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getLesserOperand().(BinaryBitwiseOperation).getValue()="1073741824"
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(RelationalOperation target_6, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getValue()="1073741824"
		and target_1.getParent().(IfStmt).getCondition()=target_6
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vsubject_52, VariableAccess target_7, ExprStmt target_8, ExprStmt target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("intsetLen")
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubject_52
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("setTypeConvert")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsubject_52
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable vserver, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="set_max_intset_entries"
		and target_4.getQualifier().(VariableAccess).getTarget()=vserver
}

predicate func_5(Parameter vsubject_52, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("setTypeConvert")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsubject_52
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
}

predicate func_6(Parameter vsubject_52, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(FunctionCall).getTarget().hasName("intsetLen")
		and target_6.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_6.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubject_52
		and target_6.getLesserOperand() instanceof ValueFieldAccess
}

predicate func_7(Variable vsuccess_64, VariableAccess target_7) {
		target_7.getTarget()=vsuccess_64
}

predicate func_8(Variable vsuccess_64, Parameter vsubject_52, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ptr"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubject_52
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("intsetAdd")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsubject_52
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("long long")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsuccess_64
}

predicate func_9(Parameter vsubject_52, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("setTypeConvert")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsubject_52
		and target_9.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
}

from Function func, Variable vsuccess_64, Variable vserver, Parameter vsubject_52, ValueFieldAccess target_4, ExprStmt target_5, RelationalOperation target_6, VariableAccess target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(target_5, func)
and not func_1(target_6, func)
and not func_2(vsubject_52, target_7, target_8, target_9)
and func_4(vserver, target_4)
and func_5(vsubject_52, target_5)
and func_6(vsubject_52, target_6)
and func_7(vsuccess_64, target_7)
and func_8(vsuccess_64, vsubject_52, target_8)
and func_9(vsubject_52, target_9)
and vsuccess_64.getType().hasName("uint8_t")
and vserver.getType().hasName("redisServer")
and vsubject_52.getType().hasName("robj *")
and vsuccess_64.(LocalVariable).getFunction() = func
and not vserver.getParentScope+() = func
and vsubject_52.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
