/**
 * @name redis-a30d367a71b7017581cf1ca104242a3c644dec0f-rdbLoadObject
 * @id cpp/redis/a30d367a71b7017581cf1ca104242a3c644dec0f/rdbLoadObject
 * @description redis-a30d367a71b7017581cf1ca104242a3c644dec0f-src/rdb.c-rdbLoadObject CVE-2021-32687
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_6, Function func) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getLesserOperand().(BinaryBitwiseOperation).getValue()="1073741824"
		and target_0.getParent().(IfStmt).getThen()=target_6
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(RelationalOperation target_7, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getValue()="1073741824"
		and target_1.getParent().(IfStmt).getCondition()=target_7
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vo_1488, Variable vlen_1489, EqualityOperation target_8, ExprStmt target_9, EqualityOperation target_10, RelationalOperation target_11) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_1489
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vo_1488
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("createSetObject")
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_1489
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dictExpand")
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_1488
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_1489
		and target_2.getElse() instanceof BlockStmt
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_10.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_11.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vserver, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="set_max_intset_entries"
		and target_4.getQualifier().(VariableAccess).getTarget()=vserver
}

predicate func_5(Variable vo_1488, RelationalOperation target_7, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vo_1488
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("createIntsetObject")
		and target_5.getParent().(IfStmt).getCondition()=target_7
}

predicate func_6(Variable vo_1488, Variable vlen_1489, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vo_1488
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("createSetObject")
		and target_6.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_1489
		and target_6.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_6.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dictExpand")
		and target_6.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_6.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_1488
		and target_6.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_1489
}

predicate func_7(Variable vlen_1489, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vlen_1489
		and target_7.getLesserOperand() instanceof ValueFieldAccess
}

predicate func_8(EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getAnOperand().(Literal).getValue()="2"
}

predicate func_9(Variable vo_1488, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("quicklistPushTail")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vo_1488
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("robj *")
		and target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("size_t")
}

predicate func_10(Variable vlen_1489, EqualityOperation target_10) {
		target_10.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_1489
		and target_10.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("rdbLoadLen")
		and target_10.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("rio *")
		and target_10.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_10.getAnOperand().(Literal).getValue()="18446744073709551615"
}

predicate func_11(Variable vlen_1489, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand().(VariableAccess).getTarget().getType().hasName("unsigned int")
		and target_11.getGreaterOperand().(VariableAccess).getTarget()=vlen_1489
}

from Function func, Variable vo_1488, Variable vlen_1489, Variable vserver, ValueFieldAccess target_4, BlockStmt target_5, BlockStmt target_6, RelationalOperation target_7, EqualityOperation target_8, ExprStmt target_9, EqualityOperation target_10, RelationalOperation target_11
where
not func_0(target_6, func)
and not func_1(target_7, func)
and not func_2(vo_1488, vlen_1489, target_8, target_9, target_10, target_11)
and func_4(vserver, target_4)
and func_5(vo_1488, target_7, target_5)
and func_6(vo_1488, vlen_1489, target_6)
and func_7(vlen_1489, target_7)
and func_8(target_8)
and func_9(vo_1488, target_9)
and func_10(vlen_1489, target_10)
and func_11(vlen_1489, target_11)
and vo_1488.getType().hasName("robj *")
and vlen_1489.getType().hasName("uint64_t")
and vserver.getType().hasName("redisServer")
and vo_1488.(LocalVariable).getFunction() = func
and vlen_1489.(LocalVariable).getFunction() = func
and not vserver.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
