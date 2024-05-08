/**
 * @name mysql-server-06588ba9c85ea453c289e353c4ded7fea664e80b-check_func_bool
 * @id cpp/mysql-server/06588ba9c85ea453c289e353c4ded7fea664e80b/checkfuncbool
 * @description mysql-server-06588ba9c85ea453c289e353c4ded7fea664e80b-storage/innobase/handler/ha_innodb.cc-check_func_bool mysql-#32851525
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(ExprStmt target_5, Function func, IfStmt target_0) {
	target_0.getCondition() instanceof LogicalOrExpr
	and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
	and target_5.getLocation().isBefore(target_0.getLocation())
	and target_0.getEnclosingFunction() = func
}

predicate func_1(EqualityOperation target_6, Function func) {
exists(IfStmt target_1 |
	exists(BlockStmt obj_0 | obj_0=target_1.getParent() |
		exists(IfStmt obj_1 | obj_1=obj_0.getParent() |
			obj_1.getThen().(BlockStmt).getStmt(5)=target_1
			and obj_1.getCondition()=target_6
		)
	)
	and target_1.getCondition() instanceof RelationalOperation
	and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
	and target_1.getEnclosingFunction() = func
)
}

predicate func_2(Variable vresult_19852, Variable vstr_19856, ReturnStmt target_7, EqualityOperation target_2) {
	exists(LogicalOrExpr obj_0 | obj_0=target_2.getParent() |
		exists(RelationalOperation obj_1 | obj_1=obj_0.getRightOperand() |
			obj_1.getLesserOperand().(VariableAccess).getTarget()=vresult_19852
			and obj_1.getGreaterOperand().(Literal).getValue()="0"
		)
		and obj_0.getParent().(IfStmt).getThen()=target_7
	)
	and target_2.getLeftOperand().(VariableAccess).getTarget()=vstr_19856
	and target_2.getRightOperand().(Literal).getValue()="0"
}

/*predicate func_3(Variable vresult_19852, Variable vstr_19856, ReturnStmt target_7, RelationalOperation target_3) {
	exists(LogicalOrExpr obj_0 | obj_0=target_3.getParent() |
		exists(EqualityOperation obj_1 | obj_1=obj_0.getLeftOperand() |
			obj_1.getLeftOperand().(VariableAccess).getTarget()=vstr_19856
			and obj_1.getRightOperand().(Literal).getValue()="0"
		)
		and obj_0.getParent().(IfStmt).getThen()=target_7
	)
	and  (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
	and target_3.getLesserOperand().(VariableAccess).getTarget()=vresult_19852
	and target_3.getGreaterOperand().(Literal).getValue()="0"
}

*/
predicate func_4(ReturnStmt target_7, Function func, LogicalOrExpr target_4) {
	target_4.getLeftOperand() instanceof EqualityOperation
	and target_4.getRightOperand() instanceof RelationalOperation
	and target_4.getParent().(IfStmt).getThen()=target_7
	and target_4.getEnclosingFunction() = func
}

predicate func_5(Variable vresult_19852, Variable vstr_19856, ExprStmt target_5) {
	exists(AssignExpr obj_0 | obj_0=target_5.getExpr() |
		exists(SubExpr obj_1 | obj_1=obj_0.getRValue() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getLeftOperand() |
				obj_2.getTarget().hasName("find_type")
				and obj_2.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("TYPELIB")
				and obj_2.getArgument(1).(VariableAccess).getTarget()=vstr_19856
				and obj_2.getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
				and obj_2.getArgument(3).(Literal).getValue()="1"
			)
			and obj_1.getRightOperand().(Literal).getValue()="1"
		)
		and obj_0.getLValue().(VariableAccess).getTarget()=vresult_19852
	)
}

predicate func_6(Function func, EqualityOperation target_6) {
	exists(VariableCall obj_0 | obj_0=target_6.getLeftOperand() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getExpr() |
			obj_1.getTarget().getName()="value_type"
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("st_mysql_value *")
		)
		and obj_0.getArgument(0).(VariableAccess).getTarget().getType().hasName("st_mysql_value *")
	)
	and target_6.getRightOperand().(Literal).getValue()="0"
	and target_6.getEnclosingFunction() = func
}

predicate func_7(LogicalOrExpr target_4, Function func, ReturnStmt target_7) {
	target_7.getExpr().(Literal).getValue()="1"
	and target_7.getParent().(IfStmt).getCondition()=target_4
	and target_7.getEnclosingFunction() = func
}

from Function func, Variable vresult_19852, Variable vstr_19856, IfStmt target_0, EqualityOperation target_2, LogicalOrExpr target_4, ExprStmt target_5, EqualityOperation target_6, ReturnStmt target_7
where
func_0(target_5, func, target_0)
and not func_1(target_6, func)
and func_2(vresult_19852, vstr_19856, target_7, target_2)
and func_4(target_7, func, target_4)
and func_5(vresult_19852, vstr_19856, target_5)
and func_6(func, target_6)
and func_7(target_4, func, target_7)
and vresult_19852.getType().hasName("int")
and vstr_19856.getType().hasName("const char *")
and vresult_19852.(LocalVariable).getFunction() = func
and vstr_19856.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
