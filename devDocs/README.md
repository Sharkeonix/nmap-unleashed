***DISCLAIMER: Already outdated.***

# Dev Docs

Was forced to create this because the code got too complex, as one wise man ones said:

> "When I wrote this code, only god and I knew how it worked.<br>
> Now only god knows it!"

So I tried to create a rough diagram of the code flow and docs for how to add / change stuff for future features.

## Code Flow
![](nmapUnleashed_CodeFlow-Base_v1.png)

## Adding new features
**Data presentation**
A-C relate to modification of the dashboard.
- In general the new field needs to be added to the dashboard layout [A].
- The insertion of the data into the new field into the table is then managed in [B] with the option to color the field according to specific values.
- The data for the field is loaded in [C] from other sources / functions or is created there.

**Functions**
- D-G relate to the integration of new functions. All new functions will be created and then centralized be called from the featureLoaderGeneral() or featureLoaderThread().
- This way new features can easily be added by inserting their call into the featureLoader functions.
- If data needs to be presented, A-C describe the necessary steps.

### Adding new feature / function with data presentation into main dashboard
1. [A] Add new field into layout for main dashboard
2. [B] Add data insertion into new field with optional coloring
3. [C] Add data loading / creation for field
4. [D(Optional)] If necessary add function in main thread for new feature
5. [E(Optional)] If necessary add function in scan thread for new feature
6. [H(Optional)] If necessary add data transfer from inside scan thread to main thread

### Adding new feature / function without data presentation
1. [F] Add new function in main thread

and / or

2. [G] Add new function in scan thread
