/**
 * @name mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-parse_gno
 * @id cpp/mysql-server/70cf38f9528fc577905053dbe95782463baff9c7/parsegno
 * @description mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-sql/rpl_gtid_set.cc-parse_gno mysql-#32103192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_451, ReturnStmt target_3, ReturnStmt target_4) {
exists(RelationalOperation target_0 |
	exists(LogicalOrExpr obj_0 | obj_0=target_0.getParent() |
		exists(RelationalOperation obj_1 | obj_1=obj_0.getLeftOperand() |
			obj_1.getLesserOperand().(VariableAccess).getTarget()=vret_451
			and obj_1.getGreaterOperand().(Literal).getValue()="0"
		)
		and obj_0.getRightOperand() instanceof EqualityOperation
		and obj_0.getParent().(IfStmt).getThen()=target_3
	)
	and  (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
	and target_0.getGreaterOperand().(VariableAccess).getTarget()=vret_451
	and target_0.getLesserOperand().(VariableAccess).getType().hasName("rpl_gno")
	and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(VariableAccess).getLocation())
)
}

predicate func_1(Variable vret_451, VariableAccess target_1) {
	target_1.getTarget()=vret_451
}

predicate func_2(Variable vret_451, ReturnStmt target_3, EqualityOperation target_2) {
	exists(LogicalOrExpr obj_0 | obj_0=target_2.getParent() |
		exists(RelationalOperation obj_1 | obj_1=obj_0.getLeftOperand() |
			obj_1.getLesserOperand().(VariableAccess).getTarget()=vret_451
			and obj_1.getGreaterOperand().(Literal).getValue()="0"
		)
		and obj_0.getParent().(IfStmt).getThen()=target_3
	)
	and target_2.getLeftOperand().(VariableAccess).getTarget()=vret_451
	and target_2.getRightOperand().(Literal).getValue()="9223372036854775807"
}

predicate func_3(Function func, ReturnStmt target_3) {
	target_3.getExpr().(UnaryMinusExpr).getValue()="-1"
	and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vret_451, ReturnStmt target_4) {
	target_4.getExpr().(VariableAccess).getTarget()=vret_451
}

from Function func, Variable vret_451, VariableAccess target_1, EqualityOperation target_2, ReturnStmt target_3, ReturnStmt target_4
where
not func_0(vret_451, target_3, target_4)
and func_1(vret_451, target_1)
and func_2(vret_451, target_3, target_2)
and func_3(func, target_3)
and func_4(vret_451, target_4)
and vret_451.getType().hasName("rpl_gno")
and vret_451.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
