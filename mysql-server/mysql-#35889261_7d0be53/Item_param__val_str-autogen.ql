/**
 * @name mysql-server-7d0be530b3828428b5d80760ad43dc4bce0adfda-Item_param__val_str
 * @id cpp/mysql-server/7d0be530b3828428b5d80760ad43dc4bce0adfda/itemparamvalstr
 * @description mysql-server-7d0be530b3828428b5d80760ad43dc4bce0adfda-sql/item.cc-Item_param__val_str mysql-#35889261
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_1, Function func) {
exists(ExprStmt target_0 |
	exists(AssignExpr obj_0 | obj_0=target_0.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="null_value"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getRValue().(Literal).getValue()="1"
	)
	and exists(BlockStmt obj_2 | obj_2=target_0.getParent() |
		exists(IfStmt obj_3 | obj_3=obj_2.getParent() |
			obj_3.getThen().(BlockStmt).getStmt(0)=target_0
			and obj_3.getCondition()=target_1
		)
	)
	and target_0.getEnclosingFunction() = func
)
}

predicate func_1(Function func, EqualityOperation target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getLeftOperand() |
		obj_0.getTarget().hasName("param_state")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and target_1.getEnclosingFunction() = func
}

from Function func, EqualityOperation target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
