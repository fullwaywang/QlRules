/**
 * @name mysql-server-7d0be530b3828428b5d80760ad43dc4bce0adfda-Item_param__fix_fields
 * @id cpp/mysql-server/7d0be530b3828428b5d80760ad43dc4bce0adfda/itemparamfixfields
 * @description mysql-server-7d0be530b3828428b5d80760ad43dc4bce0adfda-sql/item.cc-Item_param__fix_fields mysql-#35889261
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_1, Function func) {
exists(ExprStmt target_0 |
	exists(FunctionCall obj_0 | obj_0=target_0.getExpr() |
		obj_0.getTarget().hasName("set_data_type_null")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and exists(BlockStmt obj_1 | obj_1=target_0.getParent() |
		exists(IfStmt obj_2 | obj_2=obj_1.getParent() |
			obj_2.getThen().(BlockStmt).getStmt(0)=target_0
			and obj_2.getCondition()=target_1
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
